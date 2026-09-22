use std::collections::HashSet;

#[derive(Debug, Clone)]
pub enum ConnectionVerdict {
    Clean,
    Suspicious {
        reason: String,
        threat_name: String,
        severity: String,
    },
    Malicious {
        reason: String,
        threat_name: String,
        severity: String,
    },
}

#[derive(Debug, Clone)]
struct C2Pattern {
    name: &'static str,
    description: &'static str,
    port: u16,
}

#[derive(Debug, Clone)]
pub struct NetworkThreatDetector {
    malicious_ips: HashSet<String>,
    suspicious_ports: HashSet<u16>,
    c2_patterns: Vec<C2Pattern>,
}

impl NetworkThreatDetector {
    pub async fn new() -> anyhow::Result<Self> {
        let mut detector = Self {
            malicious_ips: HashSet::new(),
            suspicious_ports: HashSet::from([4444, 4445, 1337, 31337, 6667, 6697, 8888, 9001, 9050]),
            c2_patterns: vec![
                C2Pattern {
                    name: "Metasploit C2",
                    description: "common post-exploitation control channel",
                    port: 4444,
                },
                C2Pattern {
                    name: "IRC Botnet",
                    description: "classic bot command channel",
                    port: 6667,
                },
                C2Pattern {
                    name: "Backdoor Port",
                    description: "high-risk backdoor convention",
                    port: 1337,
                },
            ],
        };
        detector.load_threat_feeds().await?;
        Ok(detector)
    }

    async fn load_threat_feeds(&mut self) -> anyhow::Result<()> {
        let feed_paths = [
            "/var/lib/cybershield/feeds/malicious_ips.txt",
            "/var/lib/cybershield/feeds/c2_servers.txt",
            "config/feeds/malicious_ips.txt",
        ];

        for feed in feed_paths {
            if let Ok(content) = tokio::fs::read_to_string(feed).await {
                for line in content.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    self.malicious_ips.insert(line.to_string());
                }
            }
        }

        tracing::info!("network intel loaded: {} malicious IPs", self.malicious_ips.len());
        Ok(())
    }

    pub fn analyze_connection(&self, comm: &str, ip: &str, port: u16) -> ConnectionVerdict {
        if self.malicious_ips.contains(ip) {
            return ConnectionVerdict::Malicious {
                reason: format!("destination {ip} is on threat intelligence denylist"),
                threat_name: "Known C2 Server".to_string(),
                severity: "Critical".to_string(),
            };
        }

        if self.suspicious_ports.contains(&port) {
            let reason = self
                .c2_patterns
                .iter()
                .find(|p| p.port == port)
                .map(|p| format!("port {port} matches {} ({})", p.name, p.description))
                .unwrap_or_else(|| format!("port {port} is commonly used by malware/backdoors"));

            return ConnectionVerdict::Suspicious {
                reason,
                threat_name: "Suspicious Network Activity".to_string(),
                severity: "High".to_string(),
            };
        }

        if port == 53 && comm != "systemd-resolved" && comm != "dnsmasq" {
            return ConnectionVerdict::Suspicious {
                reason: format!("{comm} is issuing direct DNS queries"),
                threat_name: "Suspicious DNS Activity".to_string(),
                severity: "Medium".to_string(),
            };
        }

        ConnectionVerdict::Clean
    }

    pub fn ai_explanation(&self, verdict: &ConnectionVerdict, comm: &str) -> String {
        match verdict {
            ConnectionVerdict::Malicious { reason, .. } => format!(
                "Danger: process '{comm}' is contacting a known malicious host. {reason}. This can enable remote control or data theft on this device."
            ),
            ConnectionVerdict::Suspicious { reason, .. } => format!(
                "Warning: process '{comm}' made an unusual network connection. {reason}. If you do not trust this app, block and investigate."
            ),
            ConnectionVerdict::Clean => {
                format!("Process '{comm}' network behavior currently looks normal.")
            }
        }
    }
}
