use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use anyhow::{Context, Result};
use log::{error, info, warn};

use crate::uid_scanner;

const PACKAGES_LIST_PATH: &str = "/data/system/packages.list";
const MONITOR_INTERVAL: Duration = Duration::from_secs(2);

pub struct PackagesMonitor {
    sender: mpsc::Sender<()>,
    _handle: thread::JoinHandle<()>,
}

impl PackagesMonitor {
    pub fn start() -> Result<Self> {
        let (sender, receiver) = mpsc::channel();
        
        let handle = thread::spawn(move || {
            Self::monitor_loop(receiver);
        });
        
        info!("Started packages.list monitor");
        
        Ok(Self {
            sender,
            _handle: handle,
        })
    }
    
    pub fn trigger_rescan(&self) -> Result<()> {
        self.sender.send(())
            .context("Failed to send trigger signal")?;
        Ok(())
    }
    
    fn monitor_loop(receiver: mpsc::Receiver<()>) {
        let mut last_mtime = Self::get_file_mtime(PACKAGES_LIST_PATH).unwrap_or(0);
        
        loop {
            // Check for manual trigger
            if let Ok(_) = receiver.try_recv() {
                info!("Manual rescan triggered");
                if let Err(e) = Self::perform_rescan() {
                    error!("Failed to perform manual rescan: {}", e);
                }
                continue;
            }
            
            // Check file modification time
            match Self::get_file_mtime(PACKAGES_LIST_PATH) {
                Ok(current_mtime) => {
                    if current_mtime != last_mtime && last_mtime != 0 {
                        info!("packages.list modified, triggering rescan");
                        if let Err(e) = Self::perform_rescan() {
                            error!("Failed to perform rescan after file change: {}", e);
                        }
                        last_mtime = current_mtime;
                    } else if last_mtime == 0 {
                        last_mtime = current_mtime;
                    }
                }
                Err(e) => {
                    warn!("Failed to get packages.list mtime: {}", e);
                }
            }
            
            thread::sleep(MONITOR_INTERVAL);
        }
    }
    
    fn get_file_mtime(path: &str) -> Result<u64> {
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("Failed to get metadata for: {}", path))?;
        
        use std::os::unix::fs::MetadataExt;
        Ok(metadata.mtime() as u64)
    }
    
    fn perform_rescan() -> Result<()> {
        info!("Performing UID rescan");
        
        match uid_scanner::perform_uid_scan_and_submit() {
            Ok(_) => {
                info!("UID rescan completed successfully");
                Ok(())
            }
            Err(e) => {
                error!("UID rescan failed: {}", e);
                Err(e)
            }
        }
    }
}

impl Drop for PackagesMonitor {
    fn drop(&mut self) {
        info!("Stopping packages monitor");
    }
}
