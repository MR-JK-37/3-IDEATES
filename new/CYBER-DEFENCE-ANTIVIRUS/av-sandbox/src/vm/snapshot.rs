use serde::{Deserialize, Serialize};

/// VM Snapshot management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub name: String,
    pub description: String,
    pub created_at: String,
    pub size_mb: u64,
}

impl Snapshot {
    pub fn clean() -> Self {
        Self {
            name: "clean".to_string(),
            description: "Clean system baseline".to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            size_mb: 5120, // 5GB baseline
        }
    }
}
