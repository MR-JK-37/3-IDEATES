use av_service::scanner::hashdb;
use tempfile::tempdir;

#[test]
fn test_hashdb_lifecycle() {
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("test.db");

    // Initialize
    hashdb::init_db(&db_path).unwrap();

    // Add hash
    hashdb::add_hash(
        "abc123",
        "TestThreat",
        "test",
        "low",
        "unit_test"
    ).unwrap();

    // Check exists
    let result = hashdb::check_hash("abc123").unwrap();
    assert!(result.is_some());
    assert_eq!(result.unwrap().threat_name, "TestThreat");

    // Check not exists
    let result = hashdb::check_hash("xyz789").unwrap();
    assert!(result.is_none());
}
