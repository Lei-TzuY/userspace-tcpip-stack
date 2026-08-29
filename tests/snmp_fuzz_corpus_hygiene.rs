use std::collections::HashMap;
use std::path::{Path, PathBuf};

const MAX_FUZZ_INPUT_LEN: usize = 4096;
const CORPUS_DIRS: &[&str] = &[
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fuzz/corpus/snmp_message_parse"
    ),
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fuzz/corpus/snmp_ber_primitives"
    ),
];

fn corpus_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = std::fs::read_dir(dir)
        .unwrap_or_else(|err| {
            panic!(
                "fuzz corpus directory must be readable: {}: {err}",
                dir.display()
            )
        })
        .map(|entry| entry.expect("fuzz corpus directory entry must be readable"))
        .filter(|entry| {
            entry
                .file_type()
                .expect("fuzz corpus entry type must be readable")
                .is_file()
        })
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    files.sort();
    files
}

#[test]
fn persistent_fuzz_corpora_remain_nonempty_bounded_and_unique() {
    let mut seen = HashMap::<Vec<u8>, PathBuf>::new();

    for dir in CORPUS_DIRS {
        let dir = Path::new(dir);
        let files = corpus_files(dir);
        assert!(
            !files.is_empty(),
            "persistent fuzz corpus must not be empty: {}",
            dir.display()
        );

        for path in files {
            let seed = std::fs::read(&path).unwrap_or_else(|err| {
                panic!(
                    "fuzz corpus entry must be readable: {}: {err}",
                    path.display()
                )
            });

            assert!(
                !seed.is_empty(),
                "fuzz corpus entry must not be empty: {}",
                path.display()
            );
            assert!(
                seed.len() <= MAX_FUZZ_INPUT_LEN,
                "fuzz corpus entry exceeds max fuzz input length: {}: {} > {}",
                path.display(),
                seed.len(),
                MAX_FUZZ_INPUT_LEN
            );

            if let Some(existing) = seen.insert(seed, path.clone()) {
                panic!(
                    "duplicate fuzz corpus contents: {} duplicates {}",
                    path.display(),
                    existing.display()
                );
            }
        }
    }
}
