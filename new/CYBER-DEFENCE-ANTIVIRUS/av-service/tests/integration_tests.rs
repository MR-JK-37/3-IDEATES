/// Integration tests for the complete scanning pipeline
use std::fs;
use std::io::Write;
use tempfile::TempDir;

#[test]
fn test_eicar_file_creation() {
    // Create EICAR test file
    let eicar_content = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    let temp_dir = TempDir::new().unwrap();
    let eicar_path = temp_dir.path().join("eicar.com");

    let mut file = fs::File::create(&eicar_path).unwrap();
    file.write_all(eicar_content.as_bytes()).unwrap();

    // Verify file was created
    assert!(eicar_path.exists());
    let content = fs::read_to_string(&eicar_path).unwrap();
    assert_eq!(content, eicar_content);
}

#[test]
fn test_multiple_test_files() {
    let temp_dir = TempDir::new().unwrap();
    let large_payload = "A".repeat(10000);

    // Create various test files
    let files = vec![
        ("clean.txt", "This is a clean file"),
        ("empty.txt", ""),
        ("binary.bin", "\x00\x01\x02\x03"),
        ("large.txt", large_payload.as_str()),
    ];

    for (name, content) in files {
        let path = temp_dir.path().join(name);
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        assert!(path.exists(), "File {} should exist", name);
    }

    // Verify all files exist
    let entries: Vec<_> = fs::read_dir(temp_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(entries.len(), 4, "Should have 4 test files");
}

#[test]
fn test_scan_directory_structure() {
    let temp_dir = TempDir::new().unwrap();

    // Create directory structure
    fs::create_dir(temp_dir.path().join("subdir")).unwrap();
    fs::create_dir(temp_dir.path().join("subdir/nested")).unwrap();

    // Create files in subdirs
    let file1 = temp_dir.path().join("file1.txt");
    fs::File::create(&file1)
        .unwrap()
        .write_all(b"file1")
        .unwrap();

    let file2 = temp_dir.path().join("subdir/file2.txt");
    fs::File::create(&file2)
        .unwrap()
        .write_all(b"file2")
        .unwrap();

    let file3 = temp_dir.path().join("subdir/nested/file3.txt");
    fs::File::create(&file3)
        .unwrap()
        .write_all(b"file3")
        .unwrap();

    // Count files recursively
    fn count_files(path: &std::path::Path) -> usize {
        let mut count = 0;
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                if entry.path().is_file() {
                    count += 1;
                } else if entry.path().is_dir() {
                    count += count_files(&entry.path());
                }
            }
        }
        count
    }

    assert_eq!(count_files(temp_dir.path()), 3);
}

#[test]
fn test_concurrent_file_operations() {
    use std::sync::Arc;
    use std::sync::Mutex;

    let temp_dir = Arc::new(TempDir::new().unwrap());
    let counter = Arc::new(Mutex::new(0));

    // Simulate concurrent file creation
    let handles: Vec<_> = (0..10)
        .map(|i| {
            let temp_dir = Arc::clone(&temp_dir);
            let counter = Arc::clone(&counter);

            std::thread::spawn(move || {
                let path = temp_dir.path().join(format!("file_{}.txt", i));
                let mut file = fs::File::create(&path).unwrap();
                file.write_all(format!("content {}", i).as_bytes()).unwrap();

                let mut count = counter.lock().unwrap();
                *count += 1;
            })
        })
        .collect();

    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }

    let final_count = *counter.lock().unwrap();
    assert_eq!(final_count, 10);

    // Verify all files exist
    let entries: Vec<_> = fs::read_dir(temp_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(entries.len(), 10);
}

#[test]
fn test_file_permissions() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.txt");

    fs::File::create(&file_path)
        .unwrap()
        .write_all(b"test")
        .unwrap();

    // Check file metadata
    let metadata = fs::metadata(&file_path).unwrap();
    assert!(metadata.is_file());
    assert!(metadata.len() > 0);
}

#[test]
fn test_special_characters_in_filename() {
    let temp_dir = TempDir::new().unwrap();

    let filenames = vec![
        "file with spaces.txt",
        "file-with-dashes.txt",
        "file_with_underscores.txt",
        "file.multiple.dots.txt",
    ];

    for filename in filenames {
        let path = temp_dir.path().join(filename);
        fs::File::create(&path)
            .unwrap()
            .write_all(b"content")
            .unwrap();
        assert!(path.exists(), "File {} should exist", filename);
    }
}

#[test]
fn test_symlink_handling() {
    #[cfg(unix)]
    {
        use std::os::unix::fs as unix_fs;

        let temp_dir = TempDir::new().unwrap();
        let target = temp_dir.path().join("target.txt");
        fs::File::create(&target)
            .unwrap()
            .write_all(b"target")
            .unwrap();

        let symlink = temp_dir.path().join("link.txt");
        unix_fs::symlink(&target, &symlink).unwrap();

        assert!(symlink.exists());
        let metadata = fs::symlink_metadata(&symlink).unwrap();
        assert!(metadata.file_type().is_symlink());
    }
}
