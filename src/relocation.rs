use std::collections::{HashMap, HashSet};

use goblin::{
    elf::{Elf, RelocSection},
    elf64::{
        header::*,
        reloc::*,
        sym::{STB_GLOBAL, STB_WEAK, STT_SECTION},
    },
};

use crate::{
    config::Config,
    math::align_up,
    name_resolution::resolve_name,
    name_resolution::NameResolved,
    section::{ItChunk, LinkedProgram},
    FileLocation, GlobalLocation,
};

#[derive(Debug)]
pub struct Relocate {
    /// Location to patch, in the original input file section
    patch_offset: u64,
    // Size and relocation mode. For example [`R_X86_64_PC32`]. Use r_to_str to display.
    mode: u32,
    /// Relative to, "anchor"
    relative_to: RelativeTo,
    /// Constant applied to relative, i.e. "addend"
    relative_offset: i64,
}

#[derive(Debug)]
pub enum RelativeTo {
    /// Start of a section in the same compilation unit as the relocation
    Section { index: usize },
    /// Address of a symbol
    Symbol(String),
}

/// Extract relocations for a single section
pub fn extract(elf: &Elf, target_section_index: u32) -> Vec<Relocate> {
    elf.shdr_relocs
        .iter()
        .filter(|(ri, _)| elf.section_headers[*ri].sh_info == target_section_index)
        .flat_map(|(_, reloc_section)| {
            reloc_section.iter().map(|reloc| {
                let sym = elf.syms.get(reloc.r_sym).unwrap();
                let relative_to = if sym.st_info == STT_SECTION {
                    RelativeTo::Section {
                        index: sym.st_shndx,
                    }
                } else {
                    let symname = elf
                        .strtab
                        .get_at(elf.syms.get(reloc.r_sym).unwrap().st_name)
                        .unwrap();
                    RelativeTo::Symbol(symname.to_owned())
                };

                Relocate {
                    patch_offset: reloc.r_offset,
                    mode: reloc.r_type,
                    relative_to,
                    relative_offset: reloc.r_addend.unwrap_or(0),
                }
            })
        })
        .collect()
}

pub fn apply_relocations(
    config: &Config, input_files: &[FileLocation], linked: &mut LinkedProgram,
    globals: &HashMap<String, GlobalLocation>,
) -> anyhow::Result<()> {
    let mut chunk_starts = linked
        .iter_with_positions(config)
        .map(|it| it.chunk_start)
        .collect::<Vec<_>>()
        .into_iter();

    let mut anchors = resolve_relocation_symbols(config, linked, globals)?.into_iter();

    for segment in linked.segments.iter_mut() {
        for section in segment.sections.iter_mut() {
            for chunk in section.chunks.iter_mut() {
                let cs = chunk_starts.next().unwrap();

                for reloc in chunk.relocations.iter_mut() {
                    let RelocationComputed {
                        relative_to: anchor,
                        chunk_start: _,
                        offset,
                    } = anchors.next().unwrap();

                    let resolved_address = config.base_addr.checked_add(anchor).unwrap();
                    let patch_pos = reloc.patch_offset as usize;

                    // Patch
                    // See: https://docs.rs/goblin/latest/goblin/elf/reloc/index.html
                    match reloc.mode {
                        R_X86_64_PC32 => {
                            let final_value = anchor as i64 + reloc.relative_offset + offset as i64
                                - cs as i64
                                - patch_pos as i64;

                            let final_value: i32 = final_value.try_into().expect("Overflow");

                            let slice = &mut chunk.data[patch_pos..patch_pos + 4];
                            assert_eq!(slice, &[0; 4], "Must only patch over zeroes");
                            slice.copy_from_slice(&final_value.to_le_bytes());
                        },
                        R_X86_64_64 => {
                            let final_value: u64 =
                                (resolved_address as i64 + reloc.relative_offset) as u64;

                            // println!(
                            //     "APPLY RELOCATION {}: [{patch_pos:#08x}.._+8] = {final_value:#08x}",
                            //     r_to_str(reloc.mode, EM_X86_64)
                            // );

                            let slice = &mut chunk.data[patch_pos..patch_pos + 8];
                            assert_eq!(slice, &[0; 8], "Must only patch over zeroes");
                            slice.copy_from_slice(&final_value.to_le_bytes());
                        },
                        _ => panic!(
                            "Unknown relocation type: {}",
                            r_to_str(reloc.mode, EM_X86_64)
                        ),
                    }
                }
            }
        }
    }

    debug_assert!(anchors.next().is_none());

    Ok(())
}

struct RelocationComputed {
    relative_to: u64,
    offset: u64,
    chunk_start: u64,
}

/// Resolve:
/// * relative addresses used by the relocs
fn resolve_relocation_symbols(
    config: &Config, linked: &LinkedProgram, globals: &HashMap<String, GlobalLocation>,
) -> anyhow::Result<Vec<RelocationComputed>> {
    linked.iter_with_positions(config).map(|
            ItChunk {
                chunk,
                chunk_start, ..
            }
        | chunk.relocations.iter().map(move |reloc| -> anyhow::Result<RelocationComputed> {
        let (relative_to, offset) = match &reloc.relative_to {
            RelativeTo::Section { index } => {
                // Get start of section at index of the current chunk file
                let section_addr = lookup_input_section_addr(&linked, config, &chunk.file, *index).expect("Couln't resolve section in index");
                (section_addr, 0)
            },
            RelativeTo::Symbol(name) => {
                let resolved = chunk
                    .file
                    .run_for(|bytes, elf| resolve_name(&chunk.file, bytes, elf, &name))?
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "Unable to resolve symbol {name:?} in {:?}",
                            chunk.file
                        )
                    })?;

                match resolved {
                    NameResolved::Local(_) => {
                        todo!("Get local symbol {name:?} of file {:?}", chunk.file)
                    },
                    NameResolved::Import => {
                        let glob = globals.get(name.as_str()).ok_or_else(|| {
                            anyhow::anyhow!(
                                "Unable to resolve imported symbol {name:?} in {:?}",
                                chunk.file
                            )
                        })?;

                        // Get position of symbol in glob.symtab_index of glob.file
                        let (section_index, offset) =
                            glob.file.run_for(|_file, elf| {
                                let sym = elf
                                    .syms
                                    .get(glob.symtab_index as usize)
                                    .expect("Missing symbol");

                                // Binding rules are enforced when creating the global map, so no need to check here
                                (sym.st_shndx, sym.st_value)
                            })?;

                        if let Some(itc) = linked.iter_with_positions(config).find(|
                            it
                        | {
                            it.chunk.file == glob.file && it.chunk.section_index == (section_index as u32)
                        }) {
                            let addr = itc.chunk_start;
                            (addr, offset)
                        } else {
                            todo!(
                                "Section with symtab index {} from file {:?} was not included in segments, but it contains global {name:?} referenced by a relocation {:?} in {:?}",
                                glob.symtab_index,
                                glob.file,
                                reloc,
                                chunk.file,
                            );
                        }
                    },
                }
            },
        };


        Ok(RelocationComputed { relative_to, chunk_start, offset })
    })).flatten().collect::<anyhow::Result<Vec<_>>>()
}

/// Resolve a final address for an input file section
/// TODO: build a lookup table for these before
fn lookup_input_section_addr(
    linked: &LinkedProgram, config: &Config, file: &FileLocation, section_index: usize,
) -> Option<u64> {
    let mut addr = 0;
    for segment in linked.segments.iter() {
        for section in segment.sections.iter() {
            addr = align_up(addr, section.alignment());
            for chunk in section.chunks.iter() {
                addr = align_up(addr, chunk.alignment);
                if chunk.file == *file && chunk.section_index == (section_index as u32) {
                    return Some(addr);
                }
                addr += chunk.data.len() as u64;
            }
        }
        addr = align_up(segment.size(), segment.alignment().max(config.page_size));
    }

    None
}
