/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use crate::lepton_error::{Result, err_exit_code};
use bytemuck::{cast, cast_ref};
use log::info;
use wide::{CmpEq, i16x8};

use crate::ExitCode;
use crate::consts::ZIGZAG_TO_TRANSPOSED;

use super::jpeg_header::JpegHeader;

/// SAGETHUMBS PATCH (0.5.8): global coefficient-block budget mirroring the
/// C++ reference's default memory limit (jpgcoder.cc:734-752:
/// mem_limit = 1280 MiB - 128 MiB * (MAX_NUM_THREADS - 1) = 384 MiB with
/// MAX_NUM_THREADS = 8, then max_number_of_blocks = (mem_limit / 4) * 3 /
/// (sizeof(uint16_t) * 64) = 2,359,296). The upstream Rust port dropped this
/// budget: a 16384^2 4:4:4 image needs ~1.5 GiB of coefficient buffers
/// (3 components x 512 MiB) plus another full copy for progressive merge — a
/// transient ~3 GiB peak inside dllhost/explorer, far beyond the nominal
/// per-decode budget. Unlike C++ (which clamps allocations to the budget and
/// lets decoding proceed), we reject over-budget components up front with a
/// clean error: the Rust capacity checks cannot tolerate a clamped buffer.
const MAX_TOTAL_BLOCKS: u64 = ((384u64 * 1024 * 1024) / 4) * 3 / 128;

/// holds the 8x8 blocks for a given component. Since we do multithreaded encoding,
/// the image may only hold a subset of the components (specified by dpos_offset),
/// but they can be merged
pub struct BlockBasedImage {
    block_width: u32,

    original_height: u32,

    dpos_offset: u32,

    image: Vec<AlignedBlock>,
}

static EMPTY: AlignedBlock = AlignedBlock { raw_data: [0; 64] };

impl BlockBasedImage {
    // constructs new block image for the given y-coordinate range
    pub fn new(
        jpeg_header: &JpegHeader,
        component: usize,
        luma_y_start: u32,
        luma_y_end: u32,
    ) -> Result<Self> {
        let block_width = jpeg_header.cmp_info[component].bch;
        let original_height = jpeg_header.cmp_info[component].bcv;
        let max_size = block_width * original_height;

        // SAGETHUMBS PATCH (0.5.8): whole-component requirement against the
        // global block budget (see MAX_TOTAL_BLOCKS). A single component whose
        // full-height block count exceeds its share is rejected here, before
        // any allocation — every partition new() sees the same total, so the
        // first call fails cleanly and progressive merge can never accumulate
        // more than the budget.
        let total_blocks: u64 = jpeg_header
            .cmp_info
            .iter()
            .take(usize::from(jpeg_header.cmpc))
            .map(|c| u64::from(c.bch) * u64::from(c.bcv))
            .sum();
        if u64::from(max_size) > MAX_TOTAL_BLOCKS * u64::from(max_size) / total_blocks.max(1) {
            return err_exit_code(
                ExitCode::OutOfMemory,
                format!(
                    "component {component} requires {max_size} coefficient blocks, exceeding the global budget of {MAX_TOTAL_BLOCKS} (total component blocks {total_blocks})"
                ),
            );
        }

        let image_capacity = usize::try_from(
            // SAGETHUMBS PATCH (0.5.8): hostile thread-handoff ranges can invert
            // luma_y_end < luma_y_start (upstream plain `-` underflowed u32 →
            // panic in debug, huge wrap in release). Defense-in-depth behind the
            // header range validation: saturate to 0 → clean OOM-free allocation.
            (u64::from(max_size) * u64::from(luma_y_end.saturating_sub(luma_y_start))
                + u64::from(jpeg_header.cmp_info[0].bcv - 1 /* round up */))
                / u64::from(jpeg_header.cmp_info[0].bcv),
        )
        .unwrap();

        let dpos_offset = u32::try_from(
            u64::from(max_size) * u64::from(luma_y_start) / u64::from(jpeg_header.cmp_info[0].bcv),
        )
        .unwrap();

        let mut image = Vec::new();
        if let Err(e) = image.try_reserve_exact(image_capacity) {
            // If there is an out-of-memory, this is the most likely place to happen since this is the uncompressed
            // coefficient buffer.
            //
            // Handle out of memory errors gracefully, otherwise the default oom handler kills
            // the process.
            return err_exit_code(
                ExitCode::OutOfMemory,
                format!(
                    "failed to allocate block image of size {image_capacity} for component {component} with block width {block_width} and original height {original_height} (luma_y_start = {luma_y_start}, luma_y_end = {luma_y_end}) : {e}"
                ),
            );
        }

        return Ok(BlockBasedImage {
            block_width: block_width,
            original_height: original_height,
            image,
            dpos_offset: dpos_offset,
        });
    }

    /// merges a bunch of block images generated by different threads into a single one used by progressive decoding
    pub fn merge(images: &mut Vec<Vec<BlockBasedImage>>, index: usize) -> Result<Self> {
        // figure out the total size of all the blocks so we can set the capacity correctly
        let total_size = images.iter().map(|x| x[index].image.len()).sum();

        let mut contents = Vec::new();
        if let Err(e) = contents.try_reserve_exact(total_size) {
            // If there is an out-of-memory, this is the most likely place to happen since this is the uncompressed
            // coefficient buffer.
            //
            // Handle out of memory errors gracefully, otherwise the default oom handler kills
            // the process.
            return err_exit_code(
                ExitCode::OutOfMemory,
                format!("failed to allocate merged block image of size {total_size} : {e}"),
            );
        }

        let mut block_width = None;
        let mut original_height = None;

        for v in images {
            // SAGETHUMBS PATCH (0.5.8): upstream ASSERTED
            // `dpos_offset == contents.len()` here — a PANIC in ALL builds,
            // reachable on the MAIN thread for progressive files (process_
            // progressive, no catch_unwind) from a hostile EEE truncation:
            // max_dpos cutting through a middle thread partition makes the
            // truncation gate stop that partition short, so the next
            // partition's dpos_offset no longer matches the accumulated
            // contents — a process abort in the shell host. The C++ reference
            // has no such assert (its reads clamp dpos to trunc_bc-1), but
            // the Rust JPEG writers index the merged image by the full-height
            // layout, so a short partition cannot be tolerated without a fill
            // pass. Clean error instead: the caller reports the file as
            // undecodable rather than aborting.
            if v[index].dpos_offset != contents.len() as u32 {
                return err_exit_code(
                    ExitCode::BadLeptonFile,
                    format!(
                        "block image merge mismatch: partition starts at block {}, {} blocks accumulated",
                        v[index].dpos_offset,
                        contents.len()
                    ),
                );
            }

            if let Some(w) = block_width {
                assert_eq!(w, v[index].block_width, "all block_width must match")
            } else {
                block_width = Some(v[index].block_width);
            }

            if let Some(w) = original_height {
                assert_eq!(
                    w, v[index].original_height,
                    "all original_height must match"
                )
            } else {
                original_height = Some(v[index].original_height);
            }

            contents.append(&mut v[index].image);
        }

        return Ok(BlockBasedImage {
            block_width: block_width.unwrap(),
            original_height: original_height.unwrap(),
            image: contents,
            dpos_offset: 0,
        });
    }

    #[allow(dead_code)]
    pub fn dump(&self) {
        info!(
            "size = {0}, capacity = {1}, dpos_offset = {2}",
            self.image.len(),
            self.image.capacity(),
            self.dpos_offset
        );
    }

    pub fn get_block_width(&self) -> u32 {
        self.block_width
    }

    pub fn get_original_height(&self) -> u32 {
        self.original_height
    }

    /// ensure that the image is filled up to a given dpos with blank blocks and optionally
    /// write a block at the given position.
    #[inline(always)]
    pub fn fill_up_to_dpos(
        &mut self,
        dpos: u32,
        block_to_write: Option<AlignedBlock>,
    ) -> &mut AlignedBlock {
        // ensure that dpos_offset got set to the right value when we start writing
        if self.image.len() == 0 {
            debug_assert!(self.dpos_offset == dpos);
        }

        // should never underflow otherwise we are writing to the wrong part of the image
        let relative_offset = (dpos as usize)
            .checked_sub(self.dpos_offset as usize)
            .unwrap();

        if relative_offset < self.image.len() {
            // rewrite already written block
            if let Some(b) = block_to_write {
                self.image[relative_offset] = b;
            }
        } else {
            // need to extend the image length and add any necessary
            // zero blocks to fill the gap.
            assert!(
                relative_offset < self.image.capacity(),
                "capacity should be set to the exact image size to avoid reallocations"
            );

            // optimizer realizes that this is memset
            self.image
                .resize_with(relative_offset, || AlignedBlock::default());

            self.image.push(block_to_write.unwrap_or_default());
        }

        return &mut self.image[relative_offset];
    }

    pub fn set_block_data(&mut self, dpos: u32, block_data: AlignedBlock) {
        self.fill_up_to_dpos(dpos, Some(block_data));
    }

    pub fn get_block(&self, dpos: u32) -> &AlignedBlock {
        if (dpos - self.dpos_offset) as usize >= self.image.len() {
            return &EMPTY;
        } else {
            return &self.image[(dpos - self.dpos_offset) as usize];
        }
    }

    #[inline(always)]
    pub fn append_block(&mut self, block: AlignedBlock) {
        assert!(
            self.image.len() < self.image.capacity(),
            "capacity should be set correctly"
        );
        self.image.push(block);
    }

    #[inline(always)]
    pub fn get_block_mut(&mut self, dpos: u32) -> &mut AlignedBlock {
        self.fill_up_to_dpos(dpos, None)
    }
}

/// block of 64 coefficients in the aligned order, which is similar to zigzag except that the 7x7 lower right square comes first,
/// followed by the DC, followed by the edges
#[repr(C, align(32))]
pub struct AlignedBlock {
    raw_data: [i16; 64],
}

pub static EMPTY_BLOCK: AlignedBlock = AlignedBlock { raw_data: [0; 64] };

impl Default for AlignedBlock {
    fn default() -> Self {
        AlignedBlock { raw_data: [0; 64] }
    }
}

impl AlignedBlock {
    #[inline(always)]
    pub fn new(block: [i16; 64]) -> Self {
        AlignedBlock { raw_data: block }
    }

    #[inline(always)]
    pub fn as_i16x8(&self, index: usize) -> i16x8 {
        let v: &[i16x8; 8] = cast_ref(&self.raw_data);
        v[index]
    }

    #[allow(dead_code)]
    #[inline(always)]
    pub fn transpose(&self) -> AlignedBlock {
        return AlignedBlock::new(cast(i16x8::transpose(cast(*self.get_block()))));
    }

    #[inline(always)]
    pub fn get_dc(&self) -> i16 {
        return self.raw_data[0];
    }

    #[inline(always)]
    pub fn set_dc(&mut self, value: i16) {
        self.raw_data[0] = value
    }

    #[inline(always)]
    pub fn zigzag_to_transposed(a: [i16; 64]) -> AlignedBlock {
        AlignedBlock {
            raw_data: [
                a[0], a[2], a[3], a[9], a[10], a[20], a[21], a[35], a[1], a[4], a[8], a[11], a[19],
                a[22], a[34], a[36], a[5], a[7], a[12], a[18], a[23], a[33], a[37], a[48], a[6],
                a[13], a[17], a[24], a[32], a[38], a[47], a[49], a[14], a[16], a[25], a[31], a[39],
                a[46], a[50], a[57], a[15], a[26], a[30], a[40], a[45], a[51], a[56], a[58], a[27],
                a[29], a[41], a[44], a[52], a[55], a[59], a[62], a[28], a[42], a[43], a[53], a[54],
                a[60], a[61], a[63],
            ],
        }
    }

    #[inline(always)]
    pub fn zigzag_from_transposed(&self) -> AlignedBlock {
        let a = self.raw_data;
        AlignedBlock {
            raw_data: [
                a[0], a[8], a[1], a[2], a[9], a[16], a[24], a[17], a[10], a[3], a[4], a[11], a[18],
                a[25], a[32], a[40], a[33], a[26], a[19], a[12], a[5], a[6], a[13], a[20], a[27],
                a[34], a[41], a[48], a[56], a[49], a[42], a[35], a[28], a[21], a[14], a[7], a[15],
                a[22], a[29], a[36], a[43], a[50], a[57], a[58], a[51], a[44], a[37], a[30], a[23],
                a[31], a[38], a[45], a[52], a[59], a[60], a[53], a[46], a[39], a[47], a[54], a[61],
                a[62], a[55], a[63],
            ],
        }
    }

    #[inline(always)]
    pub fn get_block(&self) -> &[i16; 64] {
        return &self.raw_data;
    }

    #[inline(always)]
    pub fn get_block_mut(&mut self) -> &mut [i16; 64] {
        return &mut self.raw_data;
    }

    // used for debugging
    #[allow(dead_code)]
    pub fn get_hash(&self) -> i32 {
        let mut sum = 0;
        for i in 0..64 {
            sum += self.raw_data[i] as i32
        }
        return sum;
    }

    #[inline(always)]
    pub fn get_count_of_non_zeros_7x7(&self) -> u8 {
        /// counts a row of non-zero values in the 7x7 block
        #[inline(always)]
        fn count_non_zeros_7x7_row(v: i16x8) -> i16x8 {
            !v.simd_eq(i16x8::ZERO) & i16x8::new([0, 1, 1, 1, 1, 1, 1, 1])
        }

        let mut sum = i16x8::ZERO;
        for i in 1..8 {
            sum += count_non_zeros_7x7_row(self.as_i16x8(i));
        }

        return sum.reduce_add() as u8;
    }

    #[inline(always)]
    pub fn get_coefficient(&self, index: usize) -> i16 {
        return self.raw_data[index];
    }

    #[inline(always)]
    pub fn set_coefficient(&mut self, index: usize, v: i16) {
        self.raw_data[index] = v;
    }

    #[inline(always)]
    pub fn set_transposed_from_zigzag(&mut self, index: usize, v: i16) {
        self.raw_data[usize::from(ZIGZAG_TO_TRANSPOSED[index])] = v;
    }

    #[inline(always)]
    pub fn get_transposed_from_zigzag(&self, index: usize) -> i16 {
        return self.raw_data[usize::from(ZIGZAG_TO_TRANSPOSED[index])];
    }

    #[inline(always)]
    pub fn from_stride(&self, offset: usize, stride: usize) -> i16x8 {
        return i16x8::new([
            self.raw_data[offset],
            self.raw_data[offset + (1 * stride)],
            self.raw_data[offset + (2 * stride)],
            self.raw_data[offset + (3 * stride)],
            self.raw_data[offset + (4 * stride)],
            self.raw_data[offset + (5 * stride)],
            self.raw_data[offset + (6 * stride)],
            self.raw_data[offset + (7 * stride)],
        ]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jpeg::jpeg_header::JpegHeader;

    /// PATCH 14 discriminator (merge contiguity): a thread partition whose
    /// blocks were cut short by the EEE truncation gate (`decode_row_wrapper`
    /// stops at `component_size_in_blocks`) leaves the NEXT partition's
    /// `dpos_offset` unequal to the accumulated contents length. Upstream
    /// ASSERTED this in merge — a PANIC in ALL builds, reachable on the MAIN
    /// thread for progressive files (process_progressive, no catch_unwind) —
    /// i.e. a process abort inside the shell host. The C++ reference has no
    /// such assert (its reads clamp dpos to trunc_bc-1), but the Rust JPEG
    /// writers index the merged image by the full-height layout, so a short
    /// partition cannot be tolerated without a fill pass. Patched: a clean
    /// error, never a panic.
    #[test]
    fn merge_with_gate_truncated_partition_is_clean_error() {
        // 1-component header: bch=2, bcv=8 (a 2x2-sampled 64-row image).
        let mut jf = JpegHeader::default();
        jf.cmpc = 1;
        jf.cmp_info[0].bch = 2;
        jf.cmp_info[0].bcv = 8;
        jf.cmp_info[0].bc = 16; // bch * bcv
        jf.cmp_info[0].sfh = 1;
        jf.cmp_info[0].sfv = 1;

        // Thread 0 covers [0, 2): dpos_offset = 16*2/8 = 4 for the NEXT
        // partition. Simulate the truncation gate cutting it to ONE block.
        let mut img0 = BlockBasedImage::new(&jf, 0, 0, 2).unwrap();
        img0.append_block(AlignedBlock { raw_data: [0; 64] });
        // Thread 1 [2, 2): empty tail partition, dpos_offset = 4.
        let img1 = BlockBasedImage::new(&jf, 0, 2, 2).unwrap();

        // Unpatched: assert panic (`4 != 1`). Patched: clean error.
        let r = BlockBasedImage::merge(&mut vec![vec![img0], vec![img1]], 0);
        assert!(
            r.is_err(),
            "merge must reject a gate-truncated partition as a clean error"
        );
    }

    /// PATCH 18 discriminator (global coefficient-block budget): a hostile
    /// (or merely huge) 16384^2 4:4:4 header requires 3 x 2048^2 = 12.6M
    /// blocks, ~5x the C++-equivalent budget of 2,359,296. Upstream Rust
    /// allocated it anyway (up to ~3 GiB transient peak for progressive
    /// merge). Patched: a clean OutOfMemory error before any allocation.
    #[test]
    fn new_rejects_component_over_global_block_budget() {
        // 16384x16384 4:4:4 -> 2048x2048 blocks per component.
        let mut jf = JpegHeader::default();
        jf.cmpc = 3;
        for c in 0..3 {
            jf.cmp_info[c].bch = 2048;
            jf.cmp_info[c].bcv = 2048;
            jf.cmp_info[c].bc = 2048 * 2048;
            jf.cmp_info[c].sfh = 2;
            jf.cmp_info[c].sfv = 2;
        }
        let r = BlockBasedImage::new(&jf, 0, 0, 2048);
        assert!(
            r.is_err(),
            "over-budget component must be rejected before allocation"
        );
    }

    /// Positive control: a 4K 4:4:4 image (480x480 blocks per component,
    /// 691k blocks total) stays well within the budget and allocates.
    #[test]
    fn new_accepts_component_within_global_block_budget() {
        let mut jf = JpegHeader::default();
        jf.cmpc = 3;
        for c in 0..3 {
            jf.cmp_info[c].bch = 480;
            jf.cmp_info[c].bcv = 480;
            jf.cmp_info[c].bc = 480 * 480;
            jf.cmp_info[c].sfh = 2;
            jf.cmp_info[c].sfv = 2;
        }
        let img = BlockBasedImage::new(&jf, 0, 0, 480).unwrap();
        assert!(img.image.capacity() >= 480 * 480);
    }
}
