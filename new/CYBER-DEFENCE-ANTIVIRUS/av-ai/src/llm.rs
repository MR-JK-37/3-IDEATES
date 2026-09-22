use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

#[derive(Clone)]
pub struct LLMEngine {
    client: Client,
    ollama_url: String,
    model: String,
    online: bool,
}

#[derive(Debug, Serialize)]
struct OllamaRequest {
    model: String,
    prompt: String,
    stream: bool,
}

#[derive(Debug, Deserialize)]
struct OllamaResponse {
    response: String,
}

impl LLMEngine {
    pub async fn new() -> Result<Self> {
        let ollama_url =
            std::env::var("OLLAMA_URL").unwrap_or_else(|_| "http://localhost:11434".to_string());
        let model = std::env::var("LLM_MODEL").unwrap_or_else(|_| "llama3.2-3b".to_string());

        let client = Client::new();
        let online = Self::test_connection(&client, &ollama_url).await;
        if online {
            info!(
                "Connected to Ollama at {} using model {}",
                ollama_url, model
            );
        } else {
            warn!("Ollama not reachable. Falling back to local plain-language templates.");
        }

        Ok(Self {
            client,
            ollama_url,
            model,
            online,
        })
    }

    async fn test_connection(client: &Client, base_url: &str) -> bool {
        let tags_url = format!("{}/api/tags", base_url);
        client
            .get(tags_url)
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    pub async fn explain_threat_simple(
        &self,
        threat_name: &str,
        file_path: &str,
    ) -> Result<String> {
        let prompt = format!(
            "You explain cyber alerts to non-technical users. Use plain words only.\n\
            Threat: {threat_name}\n\
            File: {file_path}\n\
            Write 3 short sentences:\n\
            1) what this is using a simple analogy\n\
            2) what could happen if it runs\n\
            3) a clear recommendation: block or monitor\n\
            Avoid jargon and keep it calm."
        );
        self.generate_or_fallback(prompt, threat_name, file_path)
            .await
    }

    async fn generate_or_fallback(
        &self,
        prompt: String,
        threat_name: &str,
        file_path: &str,
    ) -> Result<String> {
        if !self.online {
            return Ok(local_fallback_explanation(threat_name, file_path));
        }

        let request = OllamaRequest {
            model: self.model.clone(),
            prompt,
            stream: false,
        };
        let url = format!("{}/api/generate", self.ollama_url);
        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .context("failed to send Ollama request")?;

        if !response.status().is_success() {
            warn!(
                "Ollama returned {}. Using fallback explanation.",
                response.status()
            );
            return Ok(local_fallback_explanation(threat_name, file_path));
        }

        let parsed: OllamaResponse = response
            .json()
            .await
            .context("failed to parse Ollama response")?;
        Ok(simplify_text(&parsed.response))
    }
}

fn local_fallback_explanation(threat_name: &str, file_path: &str) -> String {
    format!(
        "This looks like a dangerous file ({threat_name}) trying to run on your computer. \
If opened, it may steal information or damage files from {file_path}. \
It is safest to block it now and only allow it if you fully trust the source."
    )
}

fn simplify_text(text: &str) -> String {
    text.replace("malware", "harmful program")
        .replace("execute", "run")
        .replace("quarantine", "isolate")
        .replace("terminate", "stop")
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fallback_returns_text_when_offline() {
        let engine = LLMEngine {
            client: Client::new(),
            ollama_url: "http://127.0.0.1:11434".to_string(),
            model: "none".to_string(),
            online: false,
        };
        let text = engine
            .explain_threat_simple("Test.Threat", "/tmp/test.bin")
            .await
            .unwrap();
        assert!(!text.is_empty());
    }
}
