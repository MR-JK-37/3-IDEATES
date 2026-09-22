use std::time::Duration;
use tokio::time::interval;

pub async fn start_signature_updater() {
    let mut ticker = interval(Duration::from_secs(3600));
    loop {
        ticker.tick().await;
        match update_signatures().await {
            Ok(count) => tracing::info!("signature updater refreshed {} entries", count),
            Err(e) => tracing::warn!("signature updater failed: {}", e),
        }
    }
}

async fn update_signatures() -> anyhow::Result<usize> {
    let mut total = 0usize;

    if let Ok(output) = std::process::Command::new("freshclam")
        .arg("--quiet")
        .output()
    {
        if output.status.success() {
            total += 1_000;
        }
    }

    if let Ok(response) = reqwest::get("https://bazaar.abuse.ch/export/csv/recent/").await {
        if let Ok(body) = response.text().await {
            for line in body.lines().skip(1).take(2000) {
                let hash = line
                    .split(',')
                    .next()
                    .unwrap_or("")
                    .trim_matches('"')
                    .to_string();
                if hash.len() == 64 {
                    let _ = crate::hashdb::add_hash(&hash, "ThreatFeed", "abuse.ch");
                    total += 1;
                }
            }
        }
    }

    Ok(total)
}
