use anyhow::Result;
use tracing::info;

mod explainer;
mod llm;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_target(true)
        .with_level(true)
        .init();

    info!("╔════════════════════════════════════════╗");
    info!("║  CyberShield AI Engine (v1.0)         ║");
    info!("║  Threat Explanation & Analysis          ║");
    info!("╚════════════════════════════════════════╝");
    info!("");

    // Initialize LLM engine
    let llm_engine = match llm::LLMEngine::new().await {
        Ok(engine) => {
            info!("✅ LLM engine initialized");
            engine
        }
        Err(e) => {
            anyhow::bail!("Failed to initialize LLM engine: {}", e);
        }
    };

    // Initialize threat explainer
    let explainer = explainer::ThreatExplainer::new(llm_engine.clone());
    info!("✅ Threat explainer initialized");

    // Example: Explain a threat
    info!("🧠 Testing threat explanation...");
    match explainer
        .explain_threat(
            "Trojan.Win32.Generic.A",
            "/home/user/Downloads/document.exe",
        )
        .await
    {
        Ok(explanation) => info!("Explanation: {}", explanation),
        Err(e) => tracing::warn!("Explanation failed: {}", e),
    }

    // Start AI service
    info!("🤖 AI service ready for incoming requests");
    info!("   Listening for threat analysis requests...");

    tokio::signal::ctrl_c().await?;
    info!("🛑 AI service shutting down");

    Ok(())
}
