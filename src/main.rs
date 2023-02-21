#![feature(drain_filter)]
#![deny(unused_must_use)]

mod args;
mod config;
mod math;
mod name_resolution;
mod permissions;
mod relocation;
mod section;
mod write_elf64;

use args::Args;
use config::Config;
use goblin::elf::Elf;
use goblin::elf64::header::ET_REL;
use goblin::elf64::section_header::{SHT_NOBITS, SHT_PROGBITS};
use section::{LinkedProgram, Section};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::str;

const ENTRYPOINT: &str = "_start";

#[derive(Debug, Clone, PartialEq)]
pub enum FileLocation {
    File(PathBuf),
    Archive { path: PathBuf, member: String },
}
impl FileLocation {
    fn run_for<F: FnOnce(&[u8], &Elf) -> R, R>(&self, f: F) -> anyhow::Result<R> {
        match self {
            FileLocation::File(path) => {
                let bytes = fs::read(path)?;
                let elf = goblin::elf::Elf::parse(&bytes)?;
                Ok(f(&bytes, &elf))
            },
            FileLocation::Archive { path, member } => {
                let bytes = fs::read(path)?;
                let archive = goblin::archive::Archive::parse(&bytes)?;
                let bytes = archive.extract(&member, &bytes)?;
                let elf = goblin::elf::Elf::parse(&bytes)?;
                Ok(f(&bytes, &elf))
            },
        }
    }
}

/// Location of a global symbol
#[derive(Debug, Clone)]
pub struct GlobalLocation {
    file: FileLocation,
    symtab_index: u32,
}

fn assert_supported(_bytes: &[u8], elf: &Elf) {
    assert!(elf.is_64, "Only 64bit is supported");
    assert!(elf.little_endian, "Only little-endian is supported");
    assert_eq!(
        elf.header.e_type, ET_REL,
        "Only relocatable input files are allowed"
    );
}

fn verify_inputs(input_files: &[FileLocation]) -> anyhow::Result<()> {
    for input in input_files {
        input.run_for(assert_supported)?;
    }
    Ok(())
}

fn extract_section_names(input_files: &[FileLocation]) -> anyhow::Result<HashSet<String>> {
    let mut sections = HashSet::new();
    for input in input_files {
        input.run_for(|_bytes, elf| {
            for sh in &elf.section_headers {
                if sh.sh_type == SHT_PROGBITS || sh.sh_type == SHT_NOBITS {
                    if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
                        sections.insert(name.to_owned());
                    }
                }
            }
        })?;
    }
    Ok(sections)
}

fn locate_inputs(args: &Args) -> Vec<FileLocation> {
    let mut result = Vec::new();

    for input_path in &args.inputs {
        let Some(extension) = input_path.extension() else {
            panic!("File without extension {input_path:?}");
        };

        if extension.to_str() == Some("o") {
            result.push(FileLocation::File(PathBuf::from(input_path)));
        } else if extension.to_str() == Some("rlib") {
            let buffer = fs::read(input_path).unwrap();
            match goblin::archive::Archive::parse(&buffer) {
                Ok(archive) => {
                    for member in archive.members() {
                        if !member.ends_with(".o") {
                            continue;
                        }

                        result.push(FileLocation::Archive {
                            path: input_path.clone(),
                            member: member.to_string(),
                        });
                    }
                },
                Err(err) => panic!("ar parse error: {err:?}"),
            }
        } else {
            panic!("Unknown extension for input {input_path:?}");
        }
    }

    result
}

fn build_binary(config: &Config, linked: &LinkedProgram) -> anyhow::Result<Vec<u8>> {
    let mut result = Vec::new();
    write_elf64::write(config, &mut result, linked)?;
    Ok(result)
}

fn main() -> anyhow::Result<()> {
    let args = args::read();
    let config = Config {
        base_addr: 0x40_0000,
        segment_file_align: 0x1000,
        page_size: 0x1000,
    };

    let input_files = locate_inputs(&args);
    verify_inputs(&input_files)?;
    let section_names = extract_section_names(&input_files)?;
    let globals = name_resolution::extract_globals(&input_files)?;
    let linked = section::build(&config, &input_files, &section_names, &globals)?;
    let binary = build_binary(&config, &linked)?;
    fs::write(args.output, binary)?;
    Ok(())
}
