/// A simple thread pool implementation that can be used to evaluate closures on separate threads.
///
/// The pool will keep a number of threads equal to the number of CPUs available on the system, and
/// will reuse threads that are idle.
///
/// If more tasks are submitted than there are threads, the pool will spawn new threads to handle
/// the extra tasks.
///
/// Why write yet another threadpool? There wasn't one that was that supported dynamically growing
/// the threadpool (rayon and tokio are all fixed), which is important since otherwise there is
/// unpredicable latency when the number of tasks submitted is greater than the number of threads.
///
/// No unsafe code is used.
use std::{
    sync::{
        Arc, LazyLock, Mutex,
        mpsc::{RecvTimeoutError, Sender, channel},
    },
    thread::{self, spawn},
    time::Duration,
};

/// A trait that defines the interface for a Lepton thread pool.
/// It has a simple fire-and-forget interface, which is sufficient for the current use cases,
/// but also requires the thread pool to be static, since we don't require the thread
/// to return within a specific lifetime.
pub trait LeptonThreadPool {
    /// Returns the maximum parallelism supported by the thread pool.
    fn max_parallelism(&self) -> usize;
    /// Runs a closure on a thread from the thread pool. The thread
    /// thread lifetime is not specified, so it can must be static.
    fn run(&self, f: Box<dyn FnOnce() + Send + 'static>);
}

/// Holds either a reference to a LeptonThreadPool or an owned Box<dyn LeptonThreadPool>.
///
/// This is useful for APIs that want to accept either a reference to a static or global thread pool
/// or an owned thread pool.
pub enum ThreadPoolHolder<'a> {
    /// Reference to a LeptonThreadPool
    Dyn(&'a dyn LeptonThreadPool),
    /// Owned Box<dyn LeptonThreadPool>
    Owned(Box<dyn LeptonThreadPool>),
}

impl LeptonThreadPool for ThreadPoolHolder<'_> {
    fn max_parallelism(&self) -> usize {
        match self {
            ThreadPoolHolder::Dyn(p) => p.max_parallelism(),
            ThreadPoolHolder::Owned(p) => p.max_parallelism(),
        }
    }
    fn run(&self, f: Box<dyn FnOnce() + Send + 'static>) {
        match self {
            ThreadPoolHolder::Dyn(p) => p.run(f),
            ThreadPoolHolder::Owned(p) => p.run(f),
        }
    }
}

/// Priority levels for threads in the thread pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LeptonThreadPriority {
    /// Low priority thread
    Low,
    /// Normal priority thread, we don't touch the priority of these threads.
    #[default]
    Normal,
    /// High priority thread
    High,
}

/// A simple thread pool that spawns threads on demand and reuses them for executing closures.
/// There is no limit on the number of threads, but the number of idle threads is limited to the number of CPUs available.
#[derive(Default)]
pub struct SimpleThreadPool {
    priority: LeptonThreadPriority,
    idle_threads: LazyLock<Arc<Mutex<Vec<Sender<Box<dyn FnOnce() + Send + 'static>>>>>>,
}

impl SimpleThreadPool {
    /// Creates a new thread pool with the specified priority.
    pub const fn new(priority: LeptonThreadPriority) -> Self {
        SimpleThreadPool {
            priority,
            idle_threads: LazyLock::new(|| Arc::new(Mutex::new(Vec::new()))),
        }
    }

    /// Returns the number of idle threads in the thread pool.
    #[allow(dead_code)]
    pub fn get_idle_threads(&self) -> usize {
        self.idle_threads.lock().unwrap().len()
    }

    /// Executes a closure on a thread from the thread pool. Does not block or return any result.
    fn execute<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        if let Some(sender) = self.idle_threads.lock().unwrap().pop() {
            // SAGETHUMBS PATCH (0.5.8): the popped Sender's worker can have been
            // evicted (NUM_CPUS cap) or killed between the pop and the send;
            // upstream unwrapped this and panicked inside dllhost/explorer. A dead
            // receiver just means this worker is gone — run the task on a fresh
            // worker instead of aborting.
            let task: Box<dyn FnOnce() + Send + 'static> = Box::new(f);
            match sender.send(task) {
                Ok(()) => return,
                Err(send_err) => {
                    self.spawn_worker(send_err.0);
                    return;
                }
            }
        }
        self.spawn_worker(Box::new(f));
    }

    /// Spawns one worker thread that runs `f` and then parks in the idle list.
    fn spawn_worker(&self, f: Box<dyn FnOnce() + Send + 'static>) {
            // channel for receiving future work on this thread
            let (tx_schedule, rx_schedule): (
                std::sync::mpsc::Sender<Box<dyn FnOnce() + Send + 'static>>,
                std::sync::mpsc::Receiver<Box<dyn FnOnce() + Send + 'static>>,
            ) = channel();

            let priority = self.priority;
            // SAGETHUMBS PATCH (0.5.8): workers hold a WEAK reference to the idle
            // list instead of a strong Arc. Upstream's strong clone keeps the
            // `Mutex<Vec<Sender>>` alive as long as a worker lives, so a per-call
            // pool's channels never close when the pool is dropped: workers park on
            // `recv()` forever and every decode leaks 1-2 threads inside dllhost/
            // explorer. With a Weak, dropping the pool drops the last strong Arc,
            // which drops the Vec and every Sender; each worker's `recv()` then
            // returns Err and the worker exits. The process-global
            // `DEFAULT_THREAD_POOL` is unaffected (it is never dropped, so its
            // Weak never expires and its workers keep being reused).
            let idle_threads = Arc::downgrade(&self.idle_threads);

            spawn(move || {
                #[cfg(any(target_os = "windows", target_os = "linux"))]
                match priority {
                    LeptonThreadPriority::Low => thread_priority::set_current_thread_priority(
                        thread_priority::ThreadPriority::Min,
                    )
                    .unwrap(),
                    LeptonThreadPriority::Normal => {}
                    LeptonThreadPriority::High => thread_priority::set_current_thread_priority(
                        thread_priority::ThreadPriority::Max,
                    )
                    .unwrap(),
                }

                f();

                loop {
                    // Park in the idle list: exactly one push per completed task
                    // (the submitter pops this entry before waking us again).
                    let Some(pool) = idle_threads.upgrade() else {
                        break;
                    };
                    if let Ok(mut i) = pool.lock() {
                        // stick back into list of idle threads if there aren't more than
                        // the number of cpus already there.
                        if i.len() > *NUM_CPUS {
                            // just exits the thread
                            break;
                        }
                        i.push(tx_schedule.clone());
                        drop(i);
                    } else {
                        break;
                    }
                    // SAGETHUMBS PATCH (0.5.8): release the upgraded Arc BEFORE
                    // parking — otherwise the worker holds a strong reference while
                    // waiting, and dropping the pool cannot free the idle list (and
                    // the worker's channel) until the next liveness probe wakes it.
                    drop(pool);

                    // Wait for a task. The 250 ms timeout is a liveness probe: if the
                    // owning pool was dropped while we were parked, our own captured
                    // Sender keeps the channel open (so recv never returns
                    // Disconnected) — the upgrade check is the only exit.
                    loop {
                        match rx_schedule.recv_timeout(Duration::from_millis(250)) {
                            Ok(f) => {
                                f();
                                break;
                            }
                            Err(RecvTimeoutError::Disconnected) => break,
                            Err(RecvTimeoutError::Timeout) => {
                                // SAGETHUMBS PATCH (0.5.8): re-check pool liveness
                                // ONLY — never re-push the Sender from here. Each
                                // wake-up would duplicate the idle-list entry, and a
                                // worker later evicted by the NUM_CPUS cap would
                                // leave a stale Sender behind (send → SendError
                                // panic on the next submit).
                                if idle_threads.upgrade().is_none() {
                                    return;
                                }
                            }
                        }
                    }
                }
            });
    }
}

/// A default instance of the `SimpleThreadPool` that can be used for encoding and decoding operations.
pub static DEFAULT_THREAD_POOL: SimpleThreadPool =
    SimpleThreadPool::new(LeptonThreadPriority::Normal);

impl LeptonThreadPool for SimpleThreadPool {
    fn max_parallelism(&self) -> usize {
        *NUM_CPUS
    }
    fn run(&self, f: Box<dyn FnOnce() + Send + 'static>) {
        self.execute(f);
    }
}

static NUM_CPUS: LazyLock<usize> = LazyLock::new(|| thread::available_parallelism().unwrap().get());

#[test]
fn test_threadpool() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    let a: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));

    for _i in 0usize..100 {
        let aref = a.clone();
        DEFAULT_THREAD_POOL.execute(move || {
            aref.fetch_add(1, Ordering::AcqRel);
        });
    }

    while a.load(std::sync::atomic::Ordering::Acquire) < 100 {
        thread::yield_now();
    }

    println!("Idle threads: {}", DEFAULT_THREAD_POOL.get_idle_threads());
}

/// SAGETHUMBS PATCH regression test: a per-call pool (the SageThumbs lepton tier
/// creates one per decode) must not leak its idle list after the pool is dropped.
/// Upstream's workers hold a STRONG Arc to `Mutex<Vec<Sender>>`, so dropping the
/// pool never releases the Vec: channels stay open and every worker parks on
/// `recv()` forever (a thread leak per decode inside dllhost/explorer). With the
/// Weak-reference patch the pool drop is the last Arc owner; the Vec (and every
/// Sender) drops, each worker's `recv()` errors, and the worker exits.
///
/// This asserts the root cause directly: after `drop(pool)` the idle list Arc
/// must be gone (Weak upgrade fails). No global thread counting, so it cannot
/// race with other tests that spawn pool workers.
#[test]
fn pool_drop_releases_idle_list() {
    use std::time::{Duration, Instant};

    let pool = SimpleThreadPool::new(LeptonThreadPriority::Normal);
    // Direct access to the private field: this test lives in the same module.
    let weak = Arc::downgrade(&pool.idle_threads);

    for _ in 0..2 {
        pool.run(Box::new(|| {}));
    }
    // Wait until a worker has actually parked itself in the idle list.
    let deadline = Instant::now() + Duration::from_secs(5);
    while pool.get_idle_threads() == 0 && Instant::now() < deadline {
        thread::yield_now();
    }
    assert!(pool.get_idle_threads() > 0, "workers should have parked");
    assert!(weak.upgrade().is_some(), "idle list alive while pool is alive");

    drop(pool);

    assert!(
        weak.upgrade().is_none(),
        "dropping the pool must release the idle list (so worker channels close and workers exit)"
    );
}

/// single thread pool that creates that doesn't create any threads
#[derive(Default)]
pub struct SingleThreadPool {}

impl LeptonThreadPool for SingleThreadPool {
    fn max_parallelism(&self) -> usize {
        1
    }
    fn run(&self, _f: Box<dyn FnOnce() + Send + 'static>) {
        panic!("SingleThreadPool does not support run; execute directly instead");
    }
}
