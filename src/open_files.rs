use goblin::elf::Elf;
use memmap::MmapOptions;
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;

/// Cookie
/// TODO: include some kind input cache identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct InputId {
    file: usize,
    member: Option<usize>,
}

/// TODO: drop
#[derive(Default)]
pub struct InputCache {
    files: Vec<Arc<InputCacheItem>>,
    file_paths: Vec<PathBuf>,
}
impl InputCache {
    pub fn read_all(&mut self, inputs: &[PathBuf]) -> anyhow::Result<()> {
        for input_path in inputs {
            let Some(extension) = input_path.extension() else {
                panic!("File without extension {input_path:?}");
            };

            let file = File::open(input_path)?;
            let mmap_boxed = Box::new(unsafe { MmapOptions::new().map(&file)? });
            let mmap: &'static memmap::Mmap = Box::leak(mmap_boxed);

            if extension.to_str() == Some("o") {
                let elf = goblin::elf::Elf::parse(&mmap)?;
                self.file_paths.push(input_path.to_owned());
                self.files.push(Arc::new(InputCacheItem::Elf { mmap, elf }));
            } else if extension.to_str() == Some("rlib") {
                match goblin::archive::Archive::parse(&mmap) {
                    Ok(archive) => {
                        let mut members = Vec::new();
                        let mut member_names = Vec::new();
                        for member in archive.members() {
                            if !member.ends_with(".o") {
                                continue;
                            }

                            let bytes = archive.extract(&member, &mmap)?;
                            let elf = goblin::elf::Elf::parse(&bytes)?;
                            member_names.push(member.to_owned());
                            members.push(elf);
                        }
                        self.file_paths.push(input_path.to_owned());
                        self.files.push(Arc::new(InputCacheItem::Archive {
                            mmap,
                            members,
                            member_names,
                        }));
                    }
                    Err(err) => panic!("ar parse error: {err:?}"),
                }
            } else {
                panic!("Unknown extension for input {input_path:?}");
            }
        }

        Ok(())
    }

    pub fn get_backing_bytes(&self, id: InputId) -> &memmap::Mmap {
        let file = self.files.get(id.file).unwrap();
        match file.as_ref() {
            InputCacheItem::Elf { mmap, .. } => mmap,
            InputCacheItem::Archive { mmap, .. } => mmap, // TODO: do we have to subslice here for the selected archive?
        }
    }

    pub fn description(&self, id: InputId) -> String {
        let path = self.file_paths.get(id.file).unwrap();

        let file = self.files.get(id.file).unwrap();
        match file.as_ref() {
            InputCacheItem::Elf { .. } => format!("{path:?}"),
            InputCacheItem::Archive { member_names, .. } => format!(
                "{:?} in {path:?}",
                member_names.get(id.member.unwrap()).unwrap()
            ),
        }
    }

    pub fn get_elf(&self, id: InputId) -> &Elf<'static> {
        let file = self.files.get(id.file).unwrap();
        match file.as_ref() {
            InputCacheItem::Elf { elf, .. } => elf,
            InputCacheItem::Archive { members, .. } => members.get(id.member.unwrap()).unwrap(),
        }
    }

    pub fn iter_ids(&self) -> impl Iterator<Item = InputId> + '_ {
        self.files
            .iter()
            .enumerate()
            .flat_map(|(file, item)| item._iter_ids_helper(file))
    }

    pub fn iter(&self) -> impl Iterator<Item = &Elf<'static>> + '_ {
        self.iter_ids().map(|id| self.get_elf(id))
    }
}

/// Field order matters: dropped in order
pub enum InputCacheItem {
    Elf {
        elf: Elf<'static>,
        mmap: &'static memmap::Mmap,
    },
    Archive {
        members: Vec<Elf<'static>>,
        member_names: Vec<String>,
        mmap: &'static memmap::Mmap,
    },
}

impl InputCacheItem {
    fn _iter_ids_helper(
        &self,
        file: usize,
    ) -> itertools::Either<impl Iterator<Item = InputId> + '_, impl Iterator<Item = InputId> + '_>
    {
        match &self {
            InputCacheItem::Elf { .. } => {
                itertools::Either::Left(std::iter::once(InputId { file, member: None }))
            }
            InputCacheItem::Archive { members, .. } => {
                itertools::Either::Right(members.iter().enumerate().map(move |(i, _)| InputId {
                    file,
                    member: Some(i),
                }))
            }
        }
    }
}
