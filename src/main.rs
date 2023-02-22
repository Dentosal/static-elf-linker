#![feature(drain_filter)]
#![deny(unused_must_use)]

mod args;
mod config;
mod math;
mod name_resolution;
mod open_files;
mod permissions;
mod relocation;
mod section;
mod write_elf64;

use args::Args;
use config::Config;
use goblin::elf::Elf;
use goblin::elf64::header::ET_REL;
use goblin::elf64::section_header::{SHT_NOBITS, SHT_PROGBITS};
use open_files::{InputCache, InputId};
use section::{LinkedProgram, Section};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::str;

const ENTRYPOINT: &str = "_start";

/// Location of a global symbol
#[derive(Debug, Clone)]
pub struct GlobalLocation {
    input: InputId,
    symtab_index: u32,
}

fn verify_inputs(inputs: &InputCache) -> anyhow::Result<()> {
    for elf in inputs.iter() {
        assert!(elf.is_64, "Only 64bit is supported");
        assert!(elf.little_endian, "Only little-endian is supported");
        assert_eq!(
            elf.header.e_type, ET_REL,
            "Only relocatable input files are allowed"
        );
    }
    Ok(())
}

fn extract_section_names(inputs: &InputCache) -> anyhow::Result<HashSet<String>> {
    let mut sections = HashSet::new();
    for elf in inputs.iter() {
        for sh in &elf.section_headers {
            if sh.sh_type == SHT_PROGBITS || sh.sh_type == SHT_NOBITS {
                if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
                    sections.insert(name.to_owned());
                }
            }
        }
    }
    Ok(sections)
}

fn build_binary(
    config: &Config,
    inputs: &InputCache,
    linked: &LinkedProgram,
) -> anyhow::Result<Vec<u8>> {
    let mut result = Vec::new();
    write_elf64::write(config, inputs, &mut result, linked)?;
    Ok(result)
}

fn main() -> anyhow::Result<()> {
    let args = args::read();
    let config = Config {
        base_addr: 0x40_0000,
        segment_file_align: 0x1000,
        page_size: 0x1000,
    };

    let mut inputs = InputCache::default();
    inputs.read_all(&args.inputs)?;

    // let mut f = File::create("/tmp/linker.log").unwrap();
    // f.write_all(&format!("lolwat {input_path:?}\n").as_bytes()).unwrap();
    // f.sync_data().unwrap();

    verify_inputs(&inputs)?;
    let section_names = extract_section_names(&inputs)?;
    let globals = name_resolution::extract_globals(&inputs)?;
    let linked = section::build(&config, &inputs, &section_names, &globals)?;
    let binary = build_binary(&config, &inputs, &linked)?;
    fs::write(args.output, binary)?;
    Ok(())
}
