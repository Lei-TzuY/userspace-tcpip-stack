use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const MAX_FUZZ_INPUT_LEN: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Target {
    MessageParse,
    BerPrimitives,
}

impl Target {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "snmp_message_parse" => Ok(Self::MessageParse),
            "snmp_ber_primitives" => Ok(Self::BerPrimitives),
            _ => Err(format!(
                "unknown target {value:?}; expected snmp_message_parse or snmp_ber_primitives"
            )),
        }
    }

    fn corpus_dir(self, manifest_dir: &Path) -> PathBuf {
        let name = match self {
            Self::MessageParse => "snmp_message_parse",
            Self::BerPrimitives => "snmp_ber_primitives",
        };
        manifest_dir.join("fuzz").join("corpus").join(name)
    }
}

#[derive(Debug)]
struct Promotion {
    destination: PathBuf,
    bytes: Vec<u8>,
}

fn usage(program: &str) -> String {
    format!(
        "usage: {program} <snmp_message_parse|snmp_ber_primitives> <artifact-path-or-directory>"
    )
}

fn parse_args<I>(mut args: I) -> Result<(Target, PathBuf), String>
where
    I: Iterator<Item = String>,
{
    let program = args
        .next()
        .unwrap_or_else(|| "promote_snmp_fuzz_artifact".to_string());
    let target = args.next().ok_or_else(|| usage(&program))?;
    let artifact = args.next().ok_or_else(|| usage(&program))?;
    if args.next().is_some() {
        return Err(usage(&program));
    }
    Ok((Target::parse(&target)?, PathBuf::from(artifact)))
}

fn stable_hash(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn read_artifact(path: &Path) -> Result<Vec<u8>, String> {
    let bytes = fs::read(path)
        .map_err(|err| format!("failed to read artifact {}: {err}", path.display()))?;
    if bytes.is_empty() {
        return Err(format!("artifact must not be empty: {}", path.display()));
    }
    if bytes.len() > MAX_FUZZ_INPUT_LEN {
        return Err(format!(
            "artifact exceeds max fuzz input length: {}: {} > {}",
            path.display(),
            bytes.len(),
            MAX_FUZZ_INPUT_LEN
        ));
    }
    Ok(bytes)
}

fn files_in_dir(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let entries = fs::read_dir(dir)
        .map_err(|err| format!("failed to read artifact directory {}: {err}", dir.display()))?;
    let mut files = Vec::new();
    for entry in entries {
        let entry =
            entry.map_err(|err| format!("failed to read artifact directory entry: {err}"))?;
        let file_type = entry.file_type().map_err(|err| {
            format!(
                "failed to read artifact entry type {}: {err}",
                entry.path().display()
            )
        })?;
        if file_type.is_file() {
            files.push(entry.path());
        }
    }
    files.sort();
    Ok(files)
}

fn artifact_candidates(path: &Path) -> Result<Vec<PathBuf>, String> {
    let metadata = fs::metadata(path).map_err(|err| {
        format!(
            "failed to inspect artifact source {}: {err}",
            path.display()
        )
    })?;
    if metadata.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    if !metadata.is_dir() {
        return Err(format!(
            "artifact source must be a file or directory: {}",
            path.display()
        ));
    }

    let minimized_dir = path.join("minimized");
    if minimized_dir.is_dir() {
        let minimized = files_in_dir(&minimized_dir)?;
        if !minimized.is_empty() {
            return Ok(minimized);
        }
    }

    let files = files_in_dir(path)?;
    if files.is_empty() {
        return Err(format!(
            "artifact directory contains no files: {}",
            path.display()
        ));
    }
    Ok(files)
}

fn find_duplicate(dir: &Path, bytes: &[u8]) -> io::Result<Option<PathBuf>> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() && fs::read(entry.path())? == bytes {
            return Ok(Some(entry.path()));
        }
    }
    Ok(None)
}

fn plan_promotions(
    manifest_dir: &Path,
    target: Target,
    artifacts: &[PathBuf],
) -> Result<Vec<Promotion>, String> {
    let corpus_dir = target.corpus_dir(manifest_dir);
    let mut promotions: Vec<Promotion> = Vec::with_capacity(artifacts.len());

    for artifact in artifacts {
        let bytes = read_artifact(artifact)?;

        let duplicate = find_duplicate(&corpus_dir, &bytes).map_err(|err| {
            format!(
                "failed to inspect corpus directory {}: {err}",
                corpus_dir.display()
            )
        })?;
        if let Some(path) = duplicate {
            return Err(format!(
                "artifact is already present in the corpus: {}",
                path.display()
            ));
        }

        if promotions.iter().any(|promotion| promotion.bytes == bytes) {
            return Err(format!(
                "artifact batch contains duplicate content: {}",
                artifact.display()
            ));
        }

        let destination = corpus_dir.join(format!("regression-{:016x}.bin", stable_hash(&bytes)));
        if destination.exists() {
            return Err(format!(
                "hash collision with existing corpus entry: {}",
                destination.display()
            ));
        }
        if promotions
            .iter()
            .any(|promotion| promotion.destination == destination)
        {
            return Err(format!(
                "hash collision within artifact batch: {}",
                destination.display()
            ));
        }

        promotions.push(Promotion { destination, bytes });
    }

    Ok(promotions)
}

fn write_promotions(promotions: &[Promotion]) -> Result<Vec<PathBuf>, String> {
    let mut written: Vec<PathBuf> = Vec::with_capacity(promotions.len());
    for promotion in promotions {
        if let Err(err) = fs::write(&promotion.destination, &promotion.bytes) {
            let mut rollback_errors = Vec::new();
            for path in written.iter().rev() {
                if let Err(rollback_err) = fs::remove_file(path) {
                    rollback_errors.push(format!("{}: {rollback_err}", path.display()));
                }
            }

            let mut message = format!(
                "failed to write promoted corpus entry {}: {err}",
                promotion.destination.display()
            );
            if !rollback_errors.is_empty() {
                message.push_str(&format!(
                    "; rollback also failed for {}",
                    rollback_errors.join(", ")
                ));
            }
            return Err(message);
        }
        written.push(promotion.destination.clone());
    }
    Ok(written)
}

fn promote_batch(
    manifest_dir: &Path,
    target: Target,
    artifacts: &[PathBuf],
) -> Result<Vec<PathBuf>, String> {
    let promotions = plan_promotions(manifest_dir, target, artifacts)?;
    write_promotions(&promotions)
}

fn promote(manifest_dir: &Path, target: Target, artifact: &Path) -> Result<PathBuf, String> {
    let promoted = promote_batch(manifest_dir, target, &[artifact.to_path_buf()])?;
    promoted
        .into_iter()
        .next()
        .ok_or_else(|| "promotion unexpectedly produced no output".to_string())
}

fn main() {
    let (target, source) = match parse_args(env::args()) {
        Ok(args) => args,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(2);
        }
    };

    let artifacts = match artifact_candidates(&source) {
        Ok(artifacts) => artifacts,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    match promote_batch(manifest_dir, target, &artifacts) {
        Ok(paths) => {
            for path in paths {
                println!("promoted {}", path.display());
            }
        }
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock must be after Unix epoch")
            .as_nanos();
        let dir = env::temp_dir().join(format!("toy-tcpip-{name}-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&dir).expect("temporary directory must be creatable");
        dir
    }

    fn prepare_manifest(target: Target) -> PathBuf {
        let manifest = temp_dir("promote-fuzz-artifact");
        fs::create_dir_all(target.corpus_dir(&manifest))
            .expect("temporary corpus directory must be creatable");
        manifest
    }

    #[test]
    fn parses_supported_targets() {
        assert_eq!(
            Target::parse("snmp_message_parse"),
            Ok(Target::MessageParse)
        );
        assert_eq!(
            Target::parse("snmp_ber_primitives"),
            Ok(Target::BerPrimitives)
        );
        assert!(Target::parse("other").is_err());
    }

    #[test]
    fn artifact_directory_prefers_minimized_files() {
        let source = temp_dir("artifact-candidates");
        fs::write(source.join("crash-raw"), [1]).expect("raw artifact must be writable");
        let minimized = source.join("minimized");
        fs::create_dir(&minimized).expect("minimized directory must be creatable");
        fs::write(minimized.join("crash-b"), [2]).expect("minimized artifact must be writable");
        fs::write(minimized.join("crash-a"), [3]).expect("minimized artifact must be writable");

        assert_eq!(
            artifact_candidates(&source).expect("directory discovery must succeed"),
            vec![minimized.join("crash-a"), minimized.join("crash-b")]
        );

        fs::remove_dir_all(source).expect("temporary directory must be removable");
    }

    #[test]
    fn artifact_directory_falls_back_to_raw_files() {
        let source = temp_dir("artifact-candidates-raw");
        let minimized = source.join("minimized");
        fs::create_dir(&minimized).expect("minimized directory must be creatable");
        fs::write(source.join("crash-b"), [2]).expect("raw artifact must be writable");
        fs::write(source.join("crash-a"), [3]).expect("raw artifact must be writable");

        assert_eq!(
            artifact_candidates(&source).expect("directory discovery must succeed"),
            vec![source.join("crash-a"), source.join("crash-b")]
        );

        fs::remove_dir_all(source).expect("temporary directory must be removable");
    }

    #[test]
    fn promotes_artifact_with_deterministic_name() {
        let target = Target::MessageParse;
        let manifest = prepare_manifest(target);
        let artifact = manifest.join("crash");
        let bytes = [0x30, 0x03, 0x02, 0x01, 0x01];
        fs::write(&artifact, bytes).expect("artifact must be writable");

        let promoted = promote(&manifest, target, &artifact).expect("promotion must succeed");
        let expected = format!("regression-{:016x}.bin", stable_hash(&bytes));
        assert_eq!(
            promoted.file_name().and_then(|name| name.to_str()),
            Some(expected.as_str())
        );
        assert_eq!(
            fs::read(&promoted).expect("promoted seed must be readable"),
            bytes
        );

        fs::remove_dir_all(manifest).expect("temporary directory must be removable");
    }

    #[test]
    fn rejects_empty_oversized_and_duplicate_artifacts() {
        let target = Target::BerPrimitives;
        let manifest = prepare_manifest(target);
        let corpus_dir = target.corpus_dir(&manifest);

        let empty = manifest.join("empty");
        fs::write(&empty, []).expect("empty artifact must be writable");
        assert!(promote(&manifest, target, &empty).is_err());

        let oversized = manifest.join("oversized");
        fs::write(&oversized, vec![0_u8; MAX_FUZZ_INPUT_LEN + 1])
            .expect("oversized artifact must be writable");
        assert!(promote(&manifest, target, &oversized).is_err());

        let duplicate = manifest.join("duplicate");
        fs::write(&duplicate, [1, 2, 3]).expect("duplicate artifact must be writable");
        fs::write(corpus_dir.join("existing.bin"), [1, 2, 3])
            .expect("existing corpus entry must be writable");
        assert!(promote(&manifest, target, &duplicate).is_err());

        fs::remove_dir_all(manifest).expect("temporary directory must be removable");
    }

    #[test]
    fn batch_validation_failure_does_not_write_partial_corpus() {
        let target = Target::MessageParse;
        let manifest = prepare_manifest(target);
        let corpus_dir = target.corpus_dir(&manifest);
        let first = manifest.join("first");
        let invalid = manifest.join("invalid");
        fs::write(&first, [1, 2, 3]).expect("first artifact must be writable");
        fs::write(&invalid, []).expect("invalid artifact must be writable");

        assert!(promote_batch(&manifest, target, &[first, invalid]).is_err());
        assert!(
            files_in_dir(&corpus_dir)
                .expect("corpus directory must remain readable")
                .is_empty()
        );

        fs::remove_dir_all(manifest).expect("temporary directory must be removable");
    }

    #[test]
    fn batch_rejects_duplicate_content_without_writes() {
        let target = Target::BerPrimitives;
        let manifest = prepare_manifest(target);
        let corpus_dir = target.corpus_dir(&manifest);
        let first = manifest.join("first");
        let second = manifest.join("second");
        fs::write(&first, [4, 5, 6]).expect("first artifact must be writable");
        fs::write(&second, [4, 5, 6]).expect("second artifact must be writable");

        assert!(promote_batch(&manifest, target, &[first, second]).is_err());
        assert!(
            files_in_dir(&corpus_dir)
                .expect("corpus directory must remain readable")
                .is_empty()
        );

        fs::remove_dir_all(manifest).expect("temporary directory must be removable");
    }

    #[test]
    fn batch_promotion_writes_all_preflighted_artifacts() {
        let target = Target::MessageParse;
        let manifest = prepare_manifest(target);
        let first = manifest.join("first");
        let second = manifest.join("second");
        fs::write(&first, [7, 8, 9]).expect("first artifact must be writable");
        fs::write(&second, [10, 11, 12]).expect("second artifact must be writable");

        let promoted = promote_batch(&manifest, target, &[first, second])
            .expect("batch promotion must succeed");
        assert_eq!(promoted.len(), 2);
        assert_eq!(
            fs::read(&promoted[0]).expect("first promoted artifact must be readable"),
            [7, 8, 9]
        );
        assert_eq!(
            fs::read(&promoted[1]).expect("second promoted artifact must be readable"),
            [10, 11, 12]
        );

        fs::remove_dir_all(manifest).expect("temporary directory must be removable");
    }
}
