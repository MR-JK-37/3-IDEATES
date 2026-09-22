use crate::api::{ScanJob, ScanSource};
use std::collections::{HashSet, VecDeque};
use std::path::Path;
use tokio::sync::mpsc;
use tokio::time::Duration;

pub async fn watch_drive_mounts(scan_tx: mpsc::Sender<ScanJob>) {
    tracing::info!("drive mount watcher active");
    let mut known_mounts = get_current_mounts().await.unwrap_or_default();
    let mut interval = tokio::time::interval(Duration::from_secs(2));

    loop {
        interval.tick().await;
        let Ok(current) = get_current_mounts().await else {
            continue;
        };

        for mount_point in current.difference(&known_mounts) {
            tracing::info!("new mount detected: {}. queuing drive scan", mount_point);
            queue_mount_scan(mount_point, scan_tx.clone()).await;
        }
        known_mounts = current;
    }
}

async fn get_current_mounts() -> anyhow::Result<HashSet<String>> {
    let content = tokio::fs::read_to_string("/proc/mounts").await?;
    let mut mounts = HashSet::new();
    for line in content.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 {
            continue;
        }
        let mount_point = fields[1];
        let fs_type = fields[2];
        if !["ext4", "ntfs", "vfat", "exfat", "btrfs", "xfs", "fuseblk"].contains(&fs_type) {
            continue;
        }
        if mount_point.starts_with("/proc")
            || mount_point.starts_with("/sys")
            || mount_point.starts_with("/dev")
            || mount_point.starts_with("/run")
        {
            continue;
        }
        mounts.insert(mount_point.to_string());
    }
    Ok(mounts)
}

async fn queue_mount_scan(mount_point: &str, scan_tx: mpsc::Sender<ScanJob>) {
    let root = mount_point.to_string();
    let files = tokio::task::spawn_blocking(move || collect_scan_candidates(&root))
        .await
        .unwrap_or_default();

    for path in files {
        let _ = scan_tx
            .send(ScanJob {
                path,
                source: ScanSource::Realtime,
            })
            .await;
    }
}

fn collect_scan_candidates(root: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut queue: VecDeque<(std::path::PathBuf, usize)> = VecDeque::new();
    queue.push_back((std::path::PathBuf::from(root), 0));

    while let Some((path, depth)) = queue.pop_front() {
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if meta.is_dir() {
            if depth >= 5 {
                continue;
            }
            let Ok(entries) = std::fs::read_dir(path) else {
                continue;
            };
            for entry in entries.flatten() {
                queue.push_back((entry.path(), depth + 1));
            }
            continue;
        }
        if !meta.is_file() {
            continue;
        }
        if should_scan_file(&path) {
            out.push(path.to_string_lossy().to_string());
        }
        if out.len() >= 5000 {
            break;
        }
    }
    out
}

fn should_scan_file(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    matches!(
        ext.as_str(),
        "exe"
            | "dll"
            | "so"
            | "dylib"
            | "sh"
            | "bat"
            | "cmd"
            | "ps1"
            | "py"
            | "jar"
            | "apk"
            | "msi"
            | "deb"
            | "rpm"
            | "appimage"
            | "zip"
            | "rar"
            | "7z"
    )
}
