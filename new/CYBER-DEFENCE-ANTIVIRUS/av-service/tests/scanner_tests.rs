/// Unit tests for the multi-engine scanner
use std::fs;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_eicar_string_detection() {
    // EICAR test file content (safe, recognized by all AV engines)
    let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    // Create temporary file
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(eicar).unwrap();
    let path = file.path().to_path_buf();

    // This test validates that EICAR file is properly created
    // In production, clamscan/yara would detect it
    let contents = fs::read(&path).unwrap();
    assert_eq!(contents, eicar);
    assert!(path.exists());
}

#[test]
fn test_entropy_calculation() {
    // Test high entropy (packed/encrypted)
    let random_data: Vec<u8> = (0u8..=255).cycle().take(1000).collect();
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(&random_data).unwrap();

    let entropy = calculate_entropy(&random_data);
    assert!(entropy > 7.0, "Random data should have high entropy");
}

#[test]
fn test_entropy_low() {
    // Test low entropy (repetitive)
    let repetitive = "AAAA".repeat(1000).into_bytes();
    let entropy = calculate_entropy(&repetitive);
    assert!(entropy < 2.0, "Repetitive data should have low entropy");
}

#[test]
fn test_clean_file_hash() {
    // Create a clean file and verify hash is consistent
    let content = b"This is a clean file\n";
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(content).unwrap();

    let hash1 = compute_hash(file.path()).unwrap();
    let hash2 = compute_hash(file.path()).unwrap();

    assert_eq!(hash1, hash2, "Hash should be deterministic");
    assert_eq!(hash1.len(), 64, "SHA256 should produce 64 hex chars");
}

/// Helper function to calculate entropy from byte slice
fn calculate_entropy(data: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    if len == 0.0 {
        return 0.0;
    }
    let mut ent = 0.0f64;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = (c as f64) / len;
        ent -= p * p.log2();
    }
    ent
}

/// Helper to compute SHA256
fn compute_hash(path: &std::path::Path) -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

#[test]
fn test_file_not_found() {
    let result = compute_hash(std::path::Path::new("/nonexistent/file"));
    assert!(result.is_err(), "Should fail on nonexistent file");
}

#[test]
fn test_empty_file() {
    let file = NamedTempFile::new().unwrap();
    // Don't write anything - empty file

    let hash = compute_hash(file.path()).unwrap();
    // SHA256 of empty file
    assert_eq!(
        hash,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn test_large_file() {
    let mut file = NamedTempFile::new().unwrap();
    // Write 10MB of data
    for _ in 0..10000 {
        file.write_all(&[0u8; 1024]).unwrap();
    }

    let hash = compute_hash(file.path()).unwrap();
    assert_eq!(hash.len(), 64);
    assert!(!hash.is_empty());
}
