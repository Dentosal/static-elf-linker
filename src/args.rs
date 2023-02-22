use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Args {
    pub library_paths: Vec<PathBuf>,
    pub inputs: Vec<PathBuf>,
    pub output: PathBuf,
}

pub fn read() -> Args {
    let mut args = std::env::args().skip(1);

    let mut library_paths = Vec::new();
    let mut inputs = Vec::new();
    let mut output = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            // Known options
            "-L" => {
                let path = args.next().expect("-L value missing");
                let path = PathBuf::try_from(path).expect("Invalid path");
                if path.is_dir() {
                    library_paths.push(path);
                } else {
                    log::debug!("Ignoring a non-dir -L path {path:?}");
                }
            }
            "-o" => {
                let path = args.next().expect("-o value missing");
                let path = PathBuf::try_from(path).expect("Invalid path");
                output = Some(path);
            }
            // Ignore: Single-dash, single-value options
            "-flavor" => {
                let _ = args.next().expect("-flavor value missing");
            }
            // Ignore: No-value options
            "-nmagic" | "-Bstatic" | "-Bdynamic" | "-Wl,--as-needed" | "--as-needed"
            | "--eh-frame-hdr" | "-znoexecstack" | "--gc-sections" | "-O1" | "-pie" => {}
            // Ignore: Known equals-options
            _ if arg.starts_with("--script=") => {}
            _ if arg.starts_with("-z") && arg.contains('=') => {}
            // Not supported yet
            other if arg.starts_with('-') => {
                panic!("Unknown option {other:?}");
            }
            // Input files
            _ => {
                let path = PathBuf::try_from(arg).expect("Invalid path");
                assert!(path.is_file(), "input path must be a file ({path:?})");
                inputs.push(path);
            }
        }
    }

    Args {
        library_paths,
        inputs,
        output: output.expect("Output path missing"),
    }
}
