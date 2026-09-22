# Test Suite Documentation

## Overview

Complete test suite for the production antivirus system, covering unit tests, integration tests, performance benchmarks, and security audits.

## Running Tests

### Quick Test Run
```bash
cd av-service
cargo test --verbose
```

### Complete Test Suite
```bash
bash scripts/run-tests.sh
```

### Individual Test Suites

**Unit Tests (Core Logic)**
```bash
cd av-service
cargo test --test scanner_tests -- --nocapture
```

**Integration Tests (End-to-End Flow)**
```bash
cd av-service
cargo test --test integration_tests -- --nocapture
```

**All Tests with Output**
```bash
cd av-service
cargo test -- --nocapture --test-threads=1
```

## Test Coverage

### Phase 1: Scanner Unit Tests (`scanner_tests.rs`)
- ✅ EICAR detection
- ✅ Entropy calculation (high/low)
- ✅ File hashing (consistency)
- ✅ File not found handling
- ✅ Empty file detection
- ✅ Large file handling

### Phase 2: Integration Tests (`integration_tests.rs`)
- ✅ EICAR file creation
- ✅ Multiple test file handling
- ✅ Directory structure scanning
- ✅ Concurrent file operations
- ✅ File permissions
- ✅ Special characters in filenames
- ✅ Symlink handling

### Phase 3: Code Quality
- ✅ Rustfmt formatting
- ✅ Clippy linting
- ✅ Unused code detection

### Phase 4: Security
- ✅ Dependency vulnerability audit
- ✅ Memory safety checks

## EICAR Test File

The EICAR (European Institute for Computer Antivirus Research) test file is a standardized, harmless file recognized by all antivirus engines as a test threat.

**Location:** `tests/eicar.com`
**Content:** `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

All major AV engines (ClamAV, YARA, etc.) will detect this as:
- **Eicar-Test-Signature** (ClamAV)
- **Eicar-Test-File** (YARA)

## Continuous Integration

Tests run automatically on:
- Every commit to `main` or `develop`
- Every pull request
- Platforms: Linux, macOS, Windows
- Rust versions: stable, beta

**CI Pipeline:** `.github/workflows/test.yml`

## Performance Benchmarks

Current performance targets:

| Component | Target | Actual |
|-----------|--------|--------|
| File hash (SHA256) | <1ms | TBD |
| Hash DB lookup | <1ms | TBD |
| ClamAV scan | <10ms | TBD |
| YARA scan | <5ms | TBD |
| Total scan latency | <50ms | TBD |
| Concurrent scans (100) | No deadlock | TBD |

Run benchmarks:
```bash
cd av-service
cargo test --release
```

## Test-Driven Development

### Before Adding New Features
1. Write tests for desired behavior
2. Run tests (they fail)
3. Implement feature
4. Run tests until passing
5. Refactor with confidence

### Testing New Scan Engine Integration
```rust
#[tokio::test]
async fn test_new_engine() {
    let engine = NewEngine::new()?;
    
    // Test with EICAR
    let result = engine.scan(&eicar_path).await?;
    assert!(matches!(result, ScanResult::Malicious { .. }));
    
    // Test with clean file
    let result = engine.scan(&clean_path).await?;
    assert!(matches!(result, ScanResult::Clean));
}
```

## Troubleshooting

### Test Fails with "ClamAV not installed"
```bash
sudo apt update
sudo apt install -y clamav clamav-daemon
freshclam  # Update virus definitions
```

### Test Fails with "Symlink handling"
On Windows, symlinks may require admin privileges. Run as administrator.

### Cargo Hangs During Tests
Increase timeout:
```bash
RUST_TEST_TIME_UNIT=5000 RUST_TEST_TIME_INTEGRATION=10000 cargo test
```

### Out of Disk Space
Clean Cargo cache:
```bash
cargo clean
```

## Adding New Tests

1. Create test file in `av-service/tests/`
2. Name it `*_test.rs` or `*_tests.rs`
3. Import from modules: `use av_service::scanner::*;`
4. Use `#[test]` or `#[tokio::test]` attributes
5. Run: `cargo test --test <name>`

Example:
```rust
#[tokio::test]
async fn test_new_feature() {
    let result = new_feature().await;
    assert!(result.is_ok());
}
```

## Security Considerations

### Handling Real Malware
**NEVER commit actual malware samples to the repository.**

For testing with real samples:
1. Download from https://bazaar.abuse.ch/ (password protected)
2. Keep samples on isolated VM only
3. Store encrypted, never in git
4. Use EICAR for CI/CD tests

### Concurrent Access Safety
All tests use `tokio::test` for async-safe testing:
```rust
#[tokio::test]
async fn test_concurrent_scanning() {
    let handles: Vec<_> = (0..100)
        .map(|i| tokio::spawn(async { scan_file(i).await }))
        .collect();
    
    // All must complete without race conditions
    for h in handles {
        h.await??;
    }
}
```

## Deployment Validation

Before production deployment, verify:
1. ✅ All tests pass on Linux, macOS, Windows
2. ✅ EICAR detection 100% success rate
3. ✅ No memory leaks (check with valgrind)
4. ✅ Scan latency < 50ms
5. ✅ CPU usage < 5% idle
6. ✅ Database connection pool stable
7. ✅ Graceful shutdown without crashes

## CI/CD Status Badge

Add to README:
```markdown
[![CI Tests](https://github.com/your-org/antivirus-system/workflows/CI/badge.svg)](https://github.com/your-org/antivirus-system/actions)
```

## Contact & Support

For test-related issues:
1. Check test output: `cargo test -- --nocapture`
2. Run specific test: `cargo test test_name -- --nocapture --exact`
3. Debug: `RUST_BACKTRACE=1 cargo test --test <name>`
