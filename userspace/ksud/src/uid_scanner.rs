use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use anyhow::{Context, Result};
use log::{debug, error, info, warn};

const USER_DATA_PATH: &str = "/data/user_de/0";
const KSU_MAX_PACKAGE_NAME: usize = 256;
const KSU_MAX_UID_ENTRIES: usize = 4096;
const KERNEL_SU_OPTION: i32 = 0xDEADBEEF_u32 as i32;
const CMD_SUBMIT_USER_UIDS: i32 = 17;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct UidPackageEntry {
    uid: u32,
    package: [u8; KSU_MAX_PACKAGE_NAME],
}

impl UidPackageEntry {
    fn new(uid: u32, package: &str) -> Self {
        let mut entry = Self {
            uid,
            package: [0u8; KSU_MAX_PACKAGE_NAME],
        };
        
        let package_bytes = package.as_bytes();
        let copy_len = std::cmp::min(package_bytes.len(), KSU_MAX_PACKAGE_NAME - 1);
        entry.package[..copy_len].copy_from_slice(&package_bytes[..copy_len]);
        entry
    }
}

#[repr(C)]
struct UserspaceUidData {
    count: u32,
    entries: [UidPackageEntry; KSU_MAX_UID_ENTRIES],
}

impl UserspaceUidData {
    fn new() -> Self {
        Self {
            count: 0,
            entries: [UidPackageEntry::new(0, ""); KSU_MAX_UID_ENTRIES],
        }
    }
    
    fn add_entry(&mut self, uid: u32, package: &str) -> bool {
        if (self.count as usize) >= KSU_MAX_UID_ENTRIES {
            return false;
        }
        
        self.entries[self.count as usize] = UidPackageEntry::new(uid, package);
        self.count += 1;
        true
    }
}

fn ksuctl(cmd: i32, arg1: *const std::ffi::c_void, arg2: *const std::ffi::c_void) -> bool {
    let mut result: i32 = 0;
    
    let rtn = unsafe {
        libc::prctl(
            KERNEL_SU_OPTION,
            cmd as libc::c_ulong,
            arg1 as libc::c_ulong,
            arg2 as libc::c_ulong,
            &mut result as *mut i32 as libc::c_ulong,
        )
    };
    
    result == KERNEL_SU_OPTION && rtn == -1
}

pub fn scan_user_data_directory() -> Result<HashMap<String, u32>> {
    let mut uid_map = HashMap::new();
    
    let user_data_path = Path::new(USER_DATA_PATH);
    if !user_data_path.exists() {
        return Err(anyhow::anyhow!("User data directory does not exist: {}", USER_DATA_PATH));
    }
    
    let entries = fs::read_dir(user_data_path)
        .with_context(|| format!("Failed to read directory: {}", USER_DATA_PATH))?;
    
    let mut total_found = 0;
    let mut errors_encountered = 0;
    
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                errors_encountered += 1;
                warn!("Failed to read directory entry: {}", e);
                continue;
            }
        };
        
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        
        let package_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(name) => name,
            None => {
                errors_encountered += 1;
                warn!("Failed to get package name from path: {:?}", path);
                continue;
            }
        };
        
        if package_name == "." || package_name == ".." {
            continue;
        }
        
        if package_name.len() >= KSU_MAX_PACKAGE_NAME {
            errors_encountered += 1;
            warn!("Package name too long: {}", package_name);
            continue;
        }
        
        let metadata = match fs::metadata(&path) {
            Ok(meta) => meta,
            Err(e) => {
                errors_encountered += 1;
                debug!("Failed to get metadata for package: {} (error: {})", package_name, e);
                continue;
            }
        };
        
        let uid = metadata.uid();
        uid_map.insert(package_name.to_string(), uid);
        total_found += 1;
        
        debug!("UserDE UID: Found package: {}, uid: {}", package_name, uid);
    }
    
    if errors_encountered > 0 {
        warn!("Encountered {} errors while scanning user data directory", errors_encountered);
    }
    
    info!("UserDE UID: Scanned user data directory, found {} packages with {} errors", 
          total_found, errors_encountered);
    
    Ok(uid_map)
}

pub fn submit_uid_data_to_kernel(uid_map: &HashMap<String, u32>) -> Result<()> {
    if uid_map.is_empty() {
        warn!("No UID data to submit to kernel");
        return Ok(());
    }
    
    let mut uid_data = UserspaceUidData::new();
    
    for (package, uid) in uid_map.iter() {
        if !uid_data.add_entry(*uid, package) {
            warn!("Too many UID entries, some will be skipped");
            break;
        }
    }
    
    info!("Submitting {} uid entries to kernel", uid_data.count);
    
    let success = ksuctl(
        CMD_SUBMIT_USER_UIDS,
        &uid_data as *const _ as *const std::ffi::c_void,
        std::ptr::null(),
    );
    
    if success {
        info!("Successfully submitted UID data to kernel");
        Ok(())
    } else {
        Err(anyhow::anyhow!("Failed to submit UID data to kernel"))
    }
}

pub fn perform_uid_scan_and_submit() -> Result<()> {
    info!("Starting userspace UID scan");
    
    match scan_user_data_directory() {
        Ok(uid_map) => {
            if uid_map.is_empty() {
                warn!("No packages found in user data directory");
                return Ok(());
            }
            
            submit_uid_data_to_kernel(&uid_map)
                .context("Failed to submit UID data to kernel")?;
            
            info!("UID scan and submission completed successfully");
            Ok(())
        }
        Err(e) => {
            error!("Failed to scan user data directory: {}", e);
            Err(e)
        }
    }
}
