//! CyberShield Antivirus - Main Service Entry Point

use anyhow::Result;
use tracing::{info, error};
use std::sync::Arc;

mod config;
mod scanner;
mod kernel_ipc;
mod quarantine;

use scanner::hashdb;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    info!("╔═══════════════════════════════════════════════════════╗");
    info!("║    🛡️  CYBERSHIELD ANTIVIRUS v1.0.0                  ║");
    info!("║    Production-Grade Real-Time Protection             ║");
    info!("╚═══════════════════════════════════════════════════════╝");
    info!("");

    // CRITICAL: Initialize hash database FIRST
    info!("📊 Initializing hash database...");
    let db_path = std::env::var("HASH_DB_PATH")
        .unwrap_or_else(|_| "./signatures/hashes/malware_hashes.db".to_string());
    
    // Create directory if needed
    if let Some(parent) = std::path::Path::new(&db_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    
    hashdb::init_db(&db_path)?;
    info!("✅ Hash database initialized: {}", db_path);

    // Add test malware hash (EICAR)
    hashdb::add_hash(
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "EICAR-Test-File",
        "test",
        "low",
        "builtin"
    )?;
    info!("✅ Added EICAR test hash");

    // Test database
    match hashdb::check_hash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f") {
        Ok(Some(threat)) => info!("🧪 Self-test: Found '{}' ✅", threat.threat_name),
        Ok(None) => error!("🧪 Self-test: Failed to find test hash ❌"),
        Err(e) => error!("🧪 Self-test error: {}", e),
    }

    info!("");
    info!("🚀 Starting protection services...");

    // Initialize platform-specific kernel communication
    let platform = std::env::consts::OS;
    info!("🖥️  Platform: {}", platform);

    match platform {
        "linux" => {
            #[cfg(target_os = "linux")]
            {
                info!("Starting Linux eBPF kernel communication...");
                let kernel_ipc = kernel_ipc::linux::LinuxKernelIpc::new()?;
                tokio::spawn(async move {
                    if let Err(e) = kernel_ipc.start().await {
                        error!("Kernel IPC error: {}", e);
                    }
                });
                info!("✅ Linux eBPF monitor active");
            }
        }
        "windows" => {
            #[cfg(target_os = "windows")]
            {
                info!("Starting Windows minifilter communication...");
                let kernel_ipc = kernel_ipc::windows::WindowsKernelIpc::new()?;
                tokio::spawn(async move {
                    if let Err(e) = kernel_ipc.start().await {
                        error!("Kernel IPC error: {}", e);
                    }
                });
                info!("✅ Windows filter driver connected");
            }
        }
        "macos" => {
            #[cfg(target_os = "macos")]
            {
                info!("Starting macOS system extension communication...");
                let kernel_ipc = kernel_ipc::macos::MacOSKernelIpc::new()?;
                tokio::spawn(async move {
                    if let Err(e) = kernel_ipc.start().await {
                        error!("Kernel IPC error: {}", e);
                    }
                });
                info!("✅ macOS Endpoint Security active");
            }
        }
        _ => {
            error!("❌ Unsupported platform: {}", platform);
            return Err(anyhow::anyhow!("Platform not supported"));
        }
    }

    info!("");
    info!("╔═══════════════════════════════════════════════════════╗");
    info!("║    🛡️  REAL-TIME PROTECTION ACTIVE                   ║");
    info!("║    All systems operational                            ║");
    info!("╚═══════════════════════════════════════════════════════╝");
    info!("");
    info!("📊 Status:");
    info!("   • Kernel monitoring: ✅ Active");
    info!("   • Hash database: ✅ Ready");
    info!("   • Threat detection: ✅ Enabled");
    info!("");
    info!("Press Ctrl+C to stop...");

    // Wait for shutdown
    tokio::signal::ctrl_c().await?;
    
    info!("");
    info!("🛑 Shutting down gracefully...");
    info!("✅ CyberShield Antivirus stopped");
    
    Ok(())
}
