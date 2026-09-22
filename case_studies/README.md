# Case study — SquashFS v4.0/xz rootfs on UBI (raw NAND dump)

Real-world recovery whose failures all lived at the SquashFS level while the
image was actually valid. Companion to the ubipack case study
(`ubi_toolkit_v1.0/case_studies/`) which covers the UBI/NAND layer (page
layout with inline ECC, VID repair, data_crc audit).

The rootfs: SquashFS v4.0, xz, block 131072, 4754 inodes, 157 fragments,
bytes_used 0xe2c9fc, on a 118-LEB UBI volume.

## Lessons for similar images

1. **"Truncated xz streams" are usually not an xz problem.** Before blaming
   compression or the filesystem creator, check whether the IMAGE VIEW is
   mis-aligned. Here every metadata stream decoded partially and died
   mid-payload; the real cause was NAND page data containing vendor ECC bytes
   that shifted everything after the first 2048 B page (see the ubipack case
   study for the layout). Symptom pattern: superblock validates 100%
   (`reference-tool superblock dump` clean) but extraction fails; container-level xz headers
   and index CRCs pass; payload dies at seemingly random offsets.

2. **Walk metadata by magic + footer, not just size words.** Standard v4
   metadata is size-prefixed u16 blocks, but vendor writers may pad/misalign
   the size words by a few bytes. Robust walk: locate each xz container by
   magic `fd 37 7a 58 5a 00`, parse its block header (filter flags 0xc0 =
   comp+uncomp sizes present), verify the index CRC, then jump to the next
   stream. Validate the footer CRC (`crc32` over the 4-byte index size field
   must match the stored value) rather than trusting recorded extents.

3. **Decode with the xz CLI first, python-lzma second.** On vendor streams the
   CLI (`xz -dc --single-stream`) agrees with python but accepts some streams
   python-lzma rejects outright. Feed `FORMAT_RAW` + `FILTER_LZMA2` the FULL
   chunk including its 6-byte header — stripping the header makes the first
   payload byte parse as an LZMA2 end marker and silently yields 0 bytes.

4. **Partial decodes are evidence, not garbage.** A stream that decodes only
   the first 1332 of 8192 bytes still yields valid inode headers, directory
   entries, and table fragments. Use partial content to map the structure
   (inode table start, dir table start, fragment arrays) even while the image
   is still damaged. Never fabricate the un-decoded remainder.

5. **Superblock pointer "garbage" can be payload corruption.** Pointers that
   read as absurd values (e.g. 0x28b0d303ebba2) were literally damaged bytes
   AT the table start, not a vendor pointer convention. Adjudicate by
   decompressing the metadata block the pointer designates and checking the
   content, before inventing pointer-shift theories.

6. **Patch matrices on external extraction tools hit a wall fast.** Editing superblock fields
   (fragment_table_start, fragment count, compression id) in a damaged image
   produces cascading unrelated errors (read_id_table, read_inode, FATAL
   corruption) that do NOT localize the real defect. Fix the image bytes
   first (see lessons 1 and the ubipack differential repair), then let stock
   external readers work unchanged.

## Failure-stage triangulation (reusable diagnostic)

Different failure stages across views of the same filesystem pinpoint where
bytes diverge:

- view A fails at read_id_table, view B fails at read_fragment_table →
  tail bytes differ between the two views → one view is mis-assembled.
- superblock validates in every view → the defect is not in the header.
- container CRCs pass but payload dies → damage inside compressed data,
  i.e. the underlying storage bytes, not the container framing.
