use anyhow::Result;
use tracing::{info, warn};

mod analyzer;
mod vm;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_target(true)
        .with_level(true)
        .init();

    info!("╔════════════════════════════════════════╗");
    info!("║  CyberShield Sandbox Service (v1.0)   ║");
    info!("║  Zero-Day Detection Engine              ║");
    info!("╚════════════════════════════════════════╝");
    info!("");

    // Initialize VM manager
    let _vm_manager = match vm::VMManager::new() {
        Ok(manager) => {
            info!("✅ VM manager initialized");
            manager
        }
        Err(e) => {
            warn!("⚠️  VM manager initialization failed: {}", e);
            warn!("    Sandbox will run in limited mode");
            vm::VMManager::offline()
        }
    };

    // Initialize behavior analyzer
    let _analyzer = analyzer::BehaviorAnalyzer::new();
    info!("✅ Behavior analyzer initialized");

    // Start sandbox service
    info!("🧪 Sandbox service ready for incoming requests");
    info!("   Listening for suspicious files from av-service...");

    // Simulate service loop (would be actual API server in production)
    tokio::signal::ctrl_c().await?;
    info!("🛑 Sandbox service shutting down");

    Ok(())
}
