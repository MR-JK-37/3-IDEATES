use anyhow::Result;
use tracing::info;

pub struct LinuxKernelIpc;

impl LinuxKernelIpc {
    pub fn new() -> Result<Self> {
        info!("Linux eBPF IPC initialized");
        Ok(Self)
    }

    pub async fn start(self) -> Result<()> {
        info!("Linux kernel monitor running (stub)");
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
        }
    }
}
