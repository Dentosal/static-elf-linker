use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::ops::Range;

use goblin::{
    elf::Elf,
    elf64::{header::*, reloc::*, section_header::*, sym::*},
};

use crate::{
    config::Config,
    math::align_up,
    open_files::{InputCache, InputId},
    permissions::Permissions,
    relocation::{self, apply_relocations, Relocate},
    GlobalLocation,
};

#[derive(Debug, Clone)]
struct Patch {
    offset: usize,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
#[must_use]
pub enum InvalidPatch {
    Overlapping,
    NotInRange,
}

#[derive(Debug, Clone)]
pub struct SectionChunk {
    pub input: InputId,
    pub range_in_input: Range<usize>,
    /// Index of section in the origin file, used by relocations
    pub section_index: u32,
    /// Alignment, extracted from the section header
    pub alignment: u64,
    pub permissions: Permissions,
    pub relocations: Vec<Relocate>,
    /// Patches generated from relocations
    /// Invariant: sorted
    patches: Vec<Patch>,
}

impl SectionChunk {
    pub fn size(&self) -> u64 {
        self.range_in_input.len() as u64
    }

    pub fn patch(&mut self, at: usize, bytes: Vec<u8>) -> Result<(), InvalidPatch> {
        if at + bytes.len() >= self.size() as usize {
            return Err(InvalidPatch::NotInRange);
        }

        if self.patches.is_empty() {
            self.patches.push(Patch { offset: at, bytes });
            return Ok(());
        }

        let index = self.patches.partition_point(|p| p.offset < at);
        let prev = &self.patches[index - 1];
        if prev.offset + prev.bytes.len() >= at {
            return Err(InvalidPatch::Overlapping);
        }

        if let Some(next) = self.patches.get(index) {
            if at + bytes.len() > next.offset {
                return Err(InvalidPatch::Overlapping);
            }
        }

        self.patches.push(Patch { offset: at, bytes });
        return Ok(());
    }

    /// Write all patched bytes into a writer
    pub fn write_finalized<T: Write>(
        &self,
        inputs: &InputCache,
        target: &mut T,
    ) -> std::io::Result<()> {
        let bytes = &inputs.get_backing_bytes(self.input)[self.range_in_input.clone()];
        let mut cursor = 0;
        for patch in &self.patches {
            target.write_all(&bytes[cursor..patch.offset])?;
            target.write_all(&patch.bytes)?;
            cursor = patch.offset + patch.bytes.len();
        }
        target.write_all(&bytes[cursor..])
    }
}

fn build_section_from(input: InputId, elf: &Elf, section_name: &str) -> Vec<SectionChunk> {
    let mut result = Vec::new();

    for (i, section) in elf.section_headers.iter().enumerate() {
        let section_index: u32 = i.try_into().expect("Session header index overflow");

        if section.sh_type != SHT_PROGBITS {
            continue;
        }

        if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
            if name != section_name {
                continue;
            }

            assert_eq!(
                section.sh_addr, 0,
                "TODO: Fixed-addess blocks are not supported"
            );

            result.push(SectionChunk {
                input,
                range_in_input: section.file_range().unwrap(),
                section_index,
                alignment: section.sh_addralign,
                permissions: Permissions {
                    read: true,
                    write: (section.sh_flags as u32) & SHF_WRITE != 0,
                    execute: (section.sh_flags as u32) & SHF_EXECINSTR != 0,
                },
                relocations: relocation::extract(elf, section_index),
                patches: Vec::new(),
            });
        }
    }

    result
}

fn build_section_group(
    inputs: &InputCache,
    section_name: &str,
) -> anyhow::Result<Vec<SectionChunk>> {
    let mut section = Vec::new();

    for input_id in inputs.iter_ids() {
        let elf = inputs.get_elf(input_id);
        let addition = build_section_from(input_id, elf, section_name);
        section.extend(addition);
    }

    Ok(section)
}

#[derive(Debug)]
pub struct Section {
    pub name: String,
    pub chunks: Vec<SectionChunk>,
    pub permissions: Permissions,
}
impl Section {
    pub fn permissions(&self) -> Permissions {
        let mut perm = Permissions::default();
        for chunk in &self.chunks {
            perm.relax(chunk.permissions);
        }
        perm
    }

    pub fn alignment(&self) -> u64 {
        self.chunks.iter().map(|c| c.alignment).max().unwrap_or(0)
    }

    pub fn size(&self) -> u64 {
        let mut result = 0;
        for chunk in &self.chunks {
            result = align_up(result, chunk.alignment);
            result += chunk.size();
        }
        result
    }
}

/// Segments are the actual loadable regions, specified in the program header.
#[derive(Debug)]
pub struct Segment {
    pub sections: Vec<Section>,
}

impl Segment {
    pub fn alignment(&self) -> u64 {
        self.sections
            .iter()
            .map(|s| s.alignment())
            .max()
            .unwrap_or(0)
    }

    pub fn size(&self) -> u64 {
        let mut result = 0;
        for section in &self.sections {
            result = align_up(result, section.alignment());
            result += section.size();
        }
        result
    }

    pub fn permissions(&self) -> Permissions {
        // All sections in a segment share their permissions
        self.sections
            .first()
            .map(|s| s.permissions())
            .unwrap_or_default()
    }
}

#[derive(Debug)]
pub struct LinkedProgram {
    pub segments: Vec<Segment>,
}
impl LinkedProgram {
    pub fn segment_sizes(&self, config: &Config) -> impl Iterator<Item = u64> + '_ {
        let alignment = config.segment_file_align;
        self.segments
            .iter()
            .map(move |s| align_up(s.size(), alignment))
    }

    pub fn iter_with_positions<'a>(
        &'a self,
        config: &'a Config,
    ) -> impl Iterator<Item = ItChunk<'a>> {
        self.segments
            .iter()
            .enumerate()
            .scan(0u64, |addr, (si, segment)| {
                if si > 0 {
                    *addr += self.segments[si - 1].size();
                    *addr = align_up(*addr, segment.alignment().max(config.page_size));
                }
                Some((*addr, si, segment))
            })
            .flat_map(|(segment_start, segment_index, segment)| {
                segment
                    .sections
                    .iter()
                    .enumerate()
                    .scan(segment_start, |addr, (si, section)| {
                        *addr = align_up(*addr, section.alignment());
                        if si > 0 {
                            *addr += segment.sections[si - 1].size();
                            *addr = align_up(*addr, section.alignment());
                        }
                        Some((*addr, si, section))
                    })
                    .flat_map(move |(section_start, section_index, section)| {
                        section
                            .chunks
                            .iter()
                            .enumerate()
                            .scan(section_start, |addr, (si, chunk)| {
                                *addr = align_up(*addr, chunk.alignment);
                                if si > 0 {
                                    *addr += section.chunks[si - 1].size();
                                    *addr = align_up(*addr, chunk.alignment);
                                }
                                Some((*addr, si, chunk))
                            })
                            .map(move |(chunk_start, chunk_index, chunk)| ItChunk {
                                segment,
                                section,
                                chunk,
                                segment_index,
                                section_index,
                                chunk_index,
                                segment_start,
                                section_start,
                                chunk_start,
                            })
                    })
            })
    }
}

pub struct ItChunk<'a> {
    pub segment: &'a Segment,
    pub section: &'a Section,
    pub chunk: &'a SectionChunk,
    pub segment_index: usize,
    pub section_index: usize,
    pub chunk_index: usize,
    pub segment_start: u64,
    pub section_start: u64,
    pub chunk_start: u64,
}

/// Combine sections from different codegen units
pub fn combine_sections(
    config: &Config,
    inputs: &InputCache,
    section_names: &HashSet<String>,
) -> anyhow::Result<Vec<Section>> {
    let build_section_by_name = |section_name: &str| -> anyhow::Result<Section> {
        Ok(Section {
            name: section_name.to_owned(),
            chunks: build_section_group(&inputs, section_name)?,
            permissions: Permissions::default(),
        })
    };

    // TODO: what about unnamed sections?

    let mut result: Vec<Section> = Vec::new();
    for group_name in [".entry", ".text", ".rodata"] {
        // exact match first
        if section_names.contains(group_name) {
            result.push(build_section_by_name(group_name)?);
        }

        // exact match first
        let prefix = &format!("{group_name}.");
        for section in section_names {
            if section.starts_with(prefix) {
                result.push(build_section_by_name(section)?);
            }
        }
    }

    Ok(result)
}

/// Combines sections to segments, so that those with same permissions stay together.
/// Segments are returned in sorted order, and the resulting value is essentially
/// the loadable portion of the ELF file, excluding the BSS segment.
pub fn sections_to_segments(
    config: &Config,
    inputs: &InputCache,
    mut sections: Vec<Section>,
) -> anyhow::Result<LinkedProgram> {
    // TODO: configurable segment/section order and grouping

    // All segments are readable for now. Write+exec should be rare, so that's last.
    let order = [
        Permissions {
            read: true,
            write: false,
            execute: true,
        },
        Permissions {
            read: true,
            write: false,
            execute: false,
        },
        Permissions {
            read: true,
            write: true,
            execute: false,
        },
        Permissions {
            read: true,
            write: true,
            execute: true,
        },
    ];

    let segments: Vec<_> = order
        .into_iter()
        .map(|perms| Segment {
            sections: sections
                .drain_filter(|s| s.permissions() == perms)
                .collect(),
        })
        .filter(|segment| !segment.sections.is_empty())
        .collect();

    assert!(sections.is_empty(), "Uncollected sections");
    Ok(LinkedProgram { segments })
}

pub fn build(
    config: &Config,
    inputs: &InputCache,
    section_names: &HashSet<String>,
    globals: &HashMap<String, GlobalLocation>,
) -> anyhow::Result<LinkedProgram> {
    let sections = combine_sections(config, inputs, section_names)?;
    let mut linked = sections_to_segments(config, inputs, sections)?;
    // TODO: dead code elimination
    apply_relocations(config, inputs, &mut linked, globals)?;
    Ok(linked)
}
