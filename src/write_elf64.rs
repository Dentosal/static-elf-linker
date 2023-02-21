//! https://en.wikipedia.org/wiki/Executable_and_Linkable_Format

use std::io::Write;

use crate::{
    config::Config, math::align_up, permissions::Permissions, section::LinkedProgram, Section,
};

pub fn write_file_header<T: Write>(
    target: &mut T, entry_point: u64, program_header_count: u16,
) -> anyhow::Result<()> {
    // Magic number
    target.write_all(&[0x7f, b'E', b'L', b'F'])?;
    // 64 bit format, little-endian
    target.write_all(&[2, 1])?;
    // ELF version: 1
    target.write_all(&[1])?;
    // OS ABI: UNIX - SystemV
    target.write_all(&[0, 0])?;
    // Reserved padding
    target.write_all(&[0; 7])?;
    // File type: executable
    target.write_all(&2u16.to_le_bytes())?;
    // Target architecture: x86-64
    target.write_all(&0x3e_u16.to_le_bytes())?;
    // Another version number: 1
    target.write_all(&0x1_u32.to_le_bytes())?;

    // Entry point
    target.write_all(&entry_point.to_le_bytes())?;
    // Program header table offset: Immediately after this header
    target.write_all(&0x40_u64.to_le_bytes())?;
    // Section header table: Currently unused
    target.write_all(&0_u64.to_le_bytes())?;
    // Flags: none
    target.write_all(&0_u32.to_le_bytes())?;
    // Size of this header: 0x40 bytes
    target.write_all(&0x40_u16.to_le_bytes())?;
    // Program header entry size: 0x38 bytes
    target.write_all(&0x38_u16.to_le_bytes())?;
    // Program header entry count:
    target.write_all(&program_header_count.to_le_bytes())?;
    // Section header entry size: 0x40 bytes
    // target.write_all(&0x40_u16.to_le_bytes())?;
    target.write_all(&0_u16.to_le_bytes())?;
    // Section header entry count: Currently unused
    target.write_all(&0_u16.to_le_bytes())?;
    // Index into section header entry containing section names: Currently unused
    target.write_all(&0_u16.to_le_bytes())?;

    Ok(())
}

#[allow(dead_code)]
mod program_header_type {
    /// Program header table entry unused.
    pub const NULL: u32 = 0x00000000;
    /// Loadable segment.
    pub const LOAD: u32 = 0x00000001;
    // Dynamic linking information.
    pub const DYNAMIC: u32 = 0x00000002;
    // Interpreter information.
    pub const INTERP: u32 = 0x00000003;
    // Auxiliary information.
    pub const NOTE: u32 = 0x00000004;
    // Reserved.
    pub const SHLIB: u32 = 0x00000005;
    // Segment containing program header table itself.
    pub const PHDR: u32 = 0x00000006;
    // Thread-Local Storage template.
    pub const TLS: u32 = 0x00000007;
    // Operating system specific. Inclusive range start.
    pub const LOOS: u32 = 0x60000000;
    // Operating system specific. Inclusive range end.
    pub const HIOS: u32 = 0x6fffffff;
    // Processor specific. Inclusive range start.
    pub const LOPROC: u32 = 0x70000000;

    // Processor specific. Inclusive range end.
    pub const HIPROC: u32 = 0x7fffffff;
}

pub fn write_program_header<T: Write>(
    target: &mut T, type_: u32, flags: u32, offset: u64, v_addr: u64, p_addr: u64, filesz: u64,
    memsz: u64, align: u64,
) -> anyhow::Result<()> {
    target.write_all(&type_.to_le_bytes())?;
    target.write_all(&flags.to_le_bytes())?;
    target.write_all(&offset.to_le_bytes())?;
    target.write_all(&v_addr.to_le_bytes())?;
    target.write_all(&p_addr.to_le_bytes())?;
    target.write_all(&filesz.to_le_bytes())?;
    target.write_all(&memsz.to_le_bytes())?;
    target.write_all(&align.to_le_bytes())?;
    Ok(())
}

pub fn write<T: Write>(
    config: &Config, target: &mut T, linked: &LinkedProgram,
) -> anyhow::Result<()> {
    // TODO: merge sections into program headers at some point

    // Calculate some offsets
    let pos_after_headers = 0x40 + linked.segments.len() as u64 * 0x38;
    let pos_first_content = align_up(pos_after_headers, config.segment_file_align);

    let nth_segment_offset = |n: usize| -> u64 {
        pos_first_content + linked.segment_sizes(&config).take(n).sum::<u64>()
    };

    // File header
    write_file_header(target, config.base_addr, linked.segments.len() as u16)?;

    // Program headers
    let mut segment_vaddr = config.base_addr;
    for (i, segment) in linked.segments.iter().enumerate() {
        segment_vaddr = align_up(segment_vaddr, config.page_size);

        // TODO: support other types than bare loadable program bits

        write_program_header(
            target,
            program_header_type::LOAD,
            (segment.permissions().read as u32) << 2
                | (segment.permissions().write as u32) << 1
                | (segment.permissions().execute as u32),
            nth_segment_offset(i) as u64,
            segment_vaddr,
            segment_vaddr,
            // TODO: differing filesz, memsz values, e.g. .bss sections
            align_up(segment.size(), config.segment_file_align),
            align_up(segment.size(), config.page_size),
            config.page_size,
        )?;

        segment_vaddr += align_up(segment.size(), config.page_size);
    }

    // Align to page size
    for _ in 0..(pos_first_content - pos_after_headers) {
        target.write_all(&[0])?;
    }

    let mut position = pos_first_content;
    for segment in &linked.segments {
        for section in &segment.sections {
            // Align to section alignment
            let align_amount = align_up(position, section.alignment()) - position;
            position += align_amount;
            for _ in 0..align_amount {
                target.write_all(&[0])?;
            }

            for chunk in &section.chunks {
                target.write_all(&chunk.data)?;

                // Align to chunk alignment
                let align_amount = align_up(position, chunk.alignment) - position;
                position += align_amount;
                for _ in 0..align_amount {
                    target.write_all(&[0])?;
                }

                position += chunk.data.len() as u64;
            }
        }

        // Align to max(section_alignment, page_size)
        let alignment = segment.alignment().max(config.page_size);
        let align_amount = align_up(position, alignment) - position;
        position += align_amount;
        for _ in 0..align_amount {
            target.write_all(&[0])?;
        }
    }

    Ok(())
}
