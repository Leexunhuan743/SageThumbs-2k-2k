/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use std::io::{Read, Result, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use crate::consts::COLOR_CHANNEL_NUM_BLOCK_TYPES;
use crate::lepton_error::{ExitCode, err_exit_code};

#[derive(Debug, Clone, PartialEq)]
pub struct ThreadHandoff {
    pub luma_y_start: u32,
    pub luma_y_end: u32,
    pub segment_offset_in_file: u32,
    pub segment_size: u32,
    pub overhang_byte: u8,
    pub num_overhang_bits: u8,
    pub last_dc: [i16; 4],
}

impl ThreadHandoff {
    /// Deserializes thread handoffs from the HH marker payload. Returns a
    /// crate error (not io) so hostile-field validation can use the clean
    /// LeptonError codes.
    pub fn deserialize<R: Read>(
        num_threads: u8,
        data: &mut R,
    ) -> crate::Result<Vec<ThreadHandoff>> {
        let mut retval: Vec<ThreadHandoff> = Vec::with_capacity(num_threads as usize);

        for _i in 0..num_threads {
            let mut th = ThreadHandoff {
                luma_y_start: data.read_u16::<LittleEndian>()? as u32,
                luma_y_end: 0,             // filled in later
                segment_offset_in_file: 0, // not serialized
                segment_size: data.read_u32::<LittleEndian>()?,
                overhang_byte: data.read_u8()?,
                num_overhang_bits: data.read_u8()?,
                last_dc: [0; 4],
            };

            // SAGETHUMBS PATCH (0.5.8): validate the overhang-bit count right
            // after deserialize. C++ encoders write 0..=7 (64 - cbit2 with
            // cbit2 in (56, 64]); 0xff is the C++ legacy-mode marker, which is
            // unreachable here — legacy files carry no HH marker at all and
            // are rejected by the zero-handoff guard before deserialize. A
            // value > 8 used to flow into
            // BitWriter::reset_from_overhang_byte_and_num_bits, where
            // `64 - num_bits` underflows (debug panic; release wraps and
            // trips the has_no_remainder assert on the decode worker) — an
            // abort in the shell host.
            if th.num_overhang_bits > 8 {
                return err_exit_code(
                    ExitCode::BadLeptonFile,
                    "invalid overhang bit count in thread handoff",
                );
            }

            for j in 0..COLOR_CHANNEL_NUM_BLOCK_TYPES {
                th.last_dc[j] = data.read_i16::<LittleEndian>()?
            }
            for _j in COLOR_CHANNEL_NUM_BLOCK_TYPES..4 {
                data.read_u16::<LittleEndian>()?;
            }

            retval.push(th);
        }

        for i in 1..retval.len() {
            retval[i - 1].luma_y_end = retval[i].luma_y_start;
        }

        // last LumaYEnd is not serialzed, filled in later
        return Ok(retval);
    }

    pub fn serialize<W: Write>(data: &Vec<ThreadHandoff>, retval: &mut W) -> Result<()> {
        retval.write_u8(data.len() as u8)?;

        for th in data {
            retval.write_u16::<LittleEndian>(th.luma_y_start as u16)?;
            // SegmentOffsetInFile is not serialized to preserve compatibility with original Lepton format
            retval.write_i32::<LittleEndian>(th.segment_size as i32)?;
            retval.write_u8(th.overhang_byte)?;
            retval.write_u8(th.num_overhang_bits)?;

            for i in 0..COLOR_CHANNEL_NUM_BLOCK_TYPES {
                retval.write_i16::<LittleEndian>(th.last_dc[i])?;
            }
            for _i in COLOR_CHANNEL_NUM_BLOCK_TYPES..4 {
                retval.write_u16::<LittleEndian>(0)?;
            }
        }

        return Ok(());
    }

    // Combine two ThreadHandoff objects into a range, starting with the "from" segment, and
    // continuing until the end of the "to" segment [from, to]
    pub fn get_combine_thread_range_segment_size(
        from: &ThreadHandoff,
        to: &ThreadHandoff,
    ) -> usize {
        return (to.segment_offset_in_file - from.segment_offset_in_file + to.segment_size)
            as usize;
    }

    pub fn combine_thread_ranges(from: &ThreadHandoff, to: &ThreadHandoff) -> ThreadHandoff {
        let ret = ThreadHandoff {
            segment_offset_in_file: from.segment_offset_in_file,
            luma_y_start: from.luma_y_start,
            overhang_byte: from.overhang_byte,
            num_overhang_bits: from.num_overhang_bits,
            luma_y_end: to.luma_y_end,
            segment_size: ThreadHandoff::get_combine_thread_range_segment_size(from, to) as u32,
            last_dc: from.last_dc,
        };

        return ret;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// PATCH 15 discriminator (overhang-bit validation): `num_overhang_bits`
    /// is read raw from the hostile HH marker. C++ encoders write 0..=7
    /// (64 - cbit2 with cbit2 in (56, 64]); 0xff is the C++ legacy-mode
    /// marker, which is unreachable here — legacy files carry no HH marker
    /// and are rejected by the zero-handoff guard before deserialize. A value
    /// > 8 used to flow into
    /// `BitWriter::reset_from_overhang_byte_and_num_bits`, where `64 -
    /// num_bits` underflows (debug panic; release wraps and trips the
    /// `has_no_remainder` assert on the decode worker) — an abort in the
    /// shell host. Patched: deserialize rejects it as BadLeptonFile.
    #[test]
    fn overhang_bits_validated() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u16.to_le_bytes()); // luma_y_start
        data.extend_from_slice(&0u32.to_le_bytes()); // segment_size
        data.push(0); // overhang_byte
        data.push(255); // num_overhang_bits — hostile
        for _ in 0..3 {
            data.extend_from_slice(&0i16.to_le_bytes());
        }
        data.extend_from_slice(&0u16.to_le_bytes());
        let r = ThreadHandoff::deserialize(1, &mut Cursor::new(&data));
        assert!(
            r.is_err(),
            "num_overhang_bits > 8 must be rejected at deserialize, got {r:?}"
        );

        // Sanity: the same data with a legal value still deserializes.
        let mut ok = data.clone();
        ok[7] = 7; // num_overhang_bits at byte 7 (after start u16 + size u32 + overhang_byte)
        assert!(ThreadHandoff::deserialize(1, &mut Cursor::new(&ok)).is_ok());
    }
}
