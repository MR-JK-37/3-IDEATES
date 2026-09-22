use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use anyhow::Context;

use crate::kernel_events::{
    KernelEvent, KernelEventKind, KernelPolicyAuditRecord, PolicyDecision, PolicyOutcome,
};

pub fn evaluate_kernel_policy(event: &KernelEvent) -> PolicyOutcome {
    match event.kind {
        KernelEventKind::FileAccess => evaluate_file_policy(event),
        KernelEventKind::ProcessExec => evaluate_process_policy(event),
        KernelEventKind::NetworkConnect => evaluate_network_policy(event),
    }
}

fn evaluate_file_policy(event: &KernelEvent) -> PolicyOutcome {
    let path = event.path.clone().unwrap_or_default().to_ascii_lowercase();

    if path.ends_with(".scr")
        || path.ends_with(".pif")
        || path.contains("eicar")
        || path.ends_with(".hta")
    {
        return PolicyOutcome {
            decision: PolicyDecision::Block,
            reason: "high-risk executable/script file pattern at file access stage".to_string(),
            severity: "Critical".to_string(),
            confidence: 0.95,
        };
    }

    if path.ends_with(".ps1")
        || path.ends_with(".vbs")
        || path.ends_with(".js")
        || path.ends_with(".jar")
        || path.contains("/tmp/")
        || path.contains("/downloads/")
    {
        return PolicyOutcome {
            decision: PolicyDecision::Monitor,
            reason: "script or transient download path requires deep scan and monitoring".to_string(),
            severity: "Medium".to_string(),
            confidence: 0.72,
        };
    }

    PolicyOutcome {
        decision: PolicyDecision::Allow,
        reason: "no policy-risk indicator for this file access".to_string(),
        severity: "Low".to_string(),
        confidence: 0.25,
    }
}

fn evaluate_process_policy(event: &KernelEvent) -> PolicyOutcome {
    let path = event.path.clone().unwrap_or_default().to_ascii_lowercase();

    if path.contains("/tmp/")
        || path.contains("/var/tmp/")
        || path.ends_with(".ps1")
        || path.ends_with(".vbs")
        || path.ends_with(".js")
    {
        return PolicyOutcome {
            decision: PolicyDecision::Quarantine,
            reason: "process execution from transient/script location".to_string(),
            severity: "High".to_string(),
            confidence: 0.84,
        };
    }

    PolicyOutcome {
        decision: PolicyDecision::Monitor,
        reason: "process execution should be scanned before trust elevation".to_string(),
        severity: "Low".to_string(),
        confidence: 0.40,
    }
}

fn evaluate_network_policy(event: &KernelEvent) -> PolicyOutcome {
    let ip = event.network_ip.clone().unwrap_or_default().to_ascii_lowercase();
    let port = event.network_port.unwrap_or_default();

    if matches!(port, 4444 | 1337 | 31337) || ip.contains(".onion") {
        return PolicyOutcome {
            decision: PolicyDecision::Block,
            reason: "known high-risk command/control style destination".to_string(),
            severity: "High".to_string(),
            confidence: 0.91,
        };
    }

    if port == 0 {
        return PolicyOutcome {
            decision: PolicyDecision::Monitor,
            reason: "incomplete network metadata from kernel event".to_string(),
            severity: "Medium".to_string(),
            confidence: 0.60,
        };
    }

    PolicyOutcome {
        decision: PolicyDecision::Monitor,
        reason: "network event requires behavioral correlation".to_string(),
        severity: "Low".to_string(),
        confidence: 0.45,
    }
}

pub fn append_policy_audit(record: &KernelPolicyAuditRecord) -> anyhow::Result<()> {
    let audit_path = std::env::var("AV_POLICY_AUDIT_LOG")
        .unwrap_or_else(|_| "/tmp/cybershield-policy-audit.jsonl".to_string());

    if let Some(parent) = Path::new(&audit_path).parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!("failed to create policy audit directory: {}", parent.display())
        })?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&audit_path)
        .with_context(|| format!("failed to open policy audit log: {}", audit_path))?;

    let line = serde_json::to_string(record)?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}
