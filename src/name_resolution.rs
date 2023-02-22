use std::collections::HashMap;

use goblin::{
    elf::Elf,
    elf64::{section_header::SHT_NOBITS, sym::*},
};

use crate::{
    open_files::{InputCache, InputId},
    GlobalLocation, ENTRYPOINT,
};

fn extract_globals_from(
    input: InputId,
    elf: &Elf,
    global_symbols: &mut HashMap<String, GlobalLocation>,
) {
    // TODO: binding preference support
    // TODO: weak binds

    let strtab = elf.strtab.to_vec().unwrap();
    let shdr_strtab = elf.shdr_strtab.to_vec().unwrap();
    for (sym_idx, sym) in elf.syms.iter().enumerate() {
        let name = elf.strtab.get_at(sym.st_name).unwrap_or("");
        // println!("{name: <20}: {sym:?}");
        if sym.st_bind() == STB_GLOBAL && name == ENTRYPOINT {
            // println!("^ entrypoint ^");
        } else if sym.is_import() {
            // println!("^ import ^");
        }
        if sym.st_bind() == STB_GLOBAL && sym.st_visibility() != STV_HIDDEN && sym.st_shndx != 0 {
            // println!("^ export ^");
            let location = GlobalLocation {
                input,
                symtab_index: sym_idx.try_into().expect("Symtab index overflow"),
            };
            let old = global_symbols.insert(name.to_string(), location.clone());
            if let Some(old) = old {
                panic!("Duplicate definition of {name:?}: exists in both {old:?} and {location:?}");
            }
        }
        if sym.st_shndx != 0 {
            if let Some(section) = &elf.section_headers.get(sym.st_shndx) {
                if section.sh_type != SHT_NOBITS {
                    // dbg!(section);
                    // println!("^ has_progbits ^");
                }
            }
        }
    }
}

pub fn extract_globals(inputs: &InputCache) -> anyhow::Result<HashMap<String, GlobalLocation>> {
    let mut global_symbols: HashMap<String, GlobalLocation> = HashMap::new();
    for input in inputs.iter_ids() {
        let elf = inputs.get_elf(input);
        extract_globals_from(input, elf, &mut global_symbols);
    }
    // dbg!(&global_symbols["_start"]);
    Ok(global_symbols)
}

#[derive(Debug)]
pub enum NameResolved {
    Local(u8),
    Import,
}

pub fn resolve_name(elf: &Elf, name: &str) -> Option<NameResolved> {
    // println!("Resolving {name:?}");

    let strtab = elf.strtab.to_vec().unwrap();
    let shdr_strtab = elf.shdr_strtab.to_vec().unwrap();
    for (sym_idx, sym) in elf.syms.iter().enumerate() {
        let sym_name = elf.strtab.get_at(sym.st_name).unwrap_or("");

        if sym_name == name {
            // println!("Found {sym:?} import={}", sym.is_import());
            if sym.is_import() {
                return Some(NameResolved::Import);
            } else {
                todo!("local sym");
            }
        }
    }

    None
}
