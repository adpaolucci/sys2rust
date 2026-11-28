use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivilegeInfo {
    pub name: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElevationStatus {
    pub is_elevated: bool,
    pub integrity_level: String,
    pub privileges: Vec<PrivilegeInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailabilityReport {
    pub elevation: ElevationStatus,
    pub se_debug_available: bool,
    pub etw_session_hint: String,
    pub windows_build: String,
}

#[cfg(windows)]
#[allow(unsafe_code)]
pub fn check_elevation() -> ElevationStatus {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, LUID_AND_ATTRIBUTES, LookupPrivilegeNameW, SE_PRIVILEGE_ENABLED, TOKEN_ELEVATION,
        TOKEN_PRIVILEGES, TOKEN_QUERY, TokenElevation, TokenPrivileges,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut status = ElevationStatus {
        is_elevated: false,
        integrity_level: "Medium".to_string(),
        privileges: Vec::new(),
    };

    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return status;
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let mut ret_len = 0u32;
        if GetTokenInformation(
            token,
            TokenElevation,
            Some((&raw mut elevation).cast()),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        )
        .is_ok()
        {
            status.is_elevated = elevation.TokenIsElevated != 0;
            if status.is_elevated {
                status.integrity_level = "High".to_string();
            }
        }

        let mut priv_len = 0u32;
        let _ = GetTokenInformation(token, TokenPrivileges, None, 0, &mut priv_len);
        if priv_len > 0 {
            let mut buf = vec![0u8; priv_len as usize];
            if GetTokenInformation(
                token,
                TokenPrivileges,
                Some(buf.as_mut_ptr().cast()),
                priv_len,
                &mut priv_len,
            )
            .is_ok()
            {
                let tp = &*(buf.as_ptr().cast::<TOKEN_PRIVILEGES>());
                let count = tp.PrivilegeCount as usize;
                let base_ptr = tp.Privileges.as_ptr();
                let slice: &[LUID_AND_ATTRIBUTES] = std::slice::from_raw_parts(base_ptr, count);
                for entry in slice {
                    let mut name_buf = [0u16; 128];
                    let mut name_len = name_buf.len() as u32;
                    let name = if LookupPrivilegeNameW(
                        None,
                        &entry.Luid,
                        Some(windows::core::PWSTR(name_buf.as_mut_ptr())),
                        &mut name_len,
                    )
                    .is_ok()
                    {
                        String::from_utf16_lossy(&name_buf[..name_len as usize])
                    } else {
                        format!("LUID({}:{})", entry.Luid.HighPart, entry.Luid.LowPart)
                    };
                    status.privileges.push(PrivilegeInfo {
                        name,
                        enabled: (entry.Attributes & SE_PRIVILEGE_ENABLED)
                            != windows::Win32::Security::TOKEN_PRIVILEGES_ATTRIBUTES(0),
                    });
                }
            }
        }

        let _ = CloseHandle(token);
    }

    status
}

#[cfg(not(windows))]
pub fn check_elevation() -> ElevationStatus {
    ElevationStatus {
        is_elevated: false,
        integrity_level: "NonWindows".to_string(),
        privileges: Vec::new(),
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
pub fn enable_se_debug_privilege() -> bool {
    use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID};
    use windows::Win32::Security::{
        AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_DEBUG_NAME, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut luid = LUID::default();
        let ok = if LookupPrivilegeValueW(None, SE_DEBUG_NAME, &mut luid).is_ok() {
            let tp = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };
            AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None).is_ok()
        } else {
            false
        };
        let _ = CloseHandle(token);
        ok
    }
}

#[cfg(not(windows))]
pub fn enable_se_debug_privilege() -> bool {
    false
}

pub fn check_availability() -> AvailabilityReport {
    let elevation = check_elevation();
    let se_debug_available = elevation
        .privileges
        .iter()
        .any(|p| p.name.eq_ignore_ascii_case("SeDebugPrivilege"));
    let etw_session_hint = if elevation.is_elevated {
        "Elevated: real-time ETW Kernel-File and Kernel-Process sessions available".to_string()
    } else {
        "Non-elevated: ETW real-time Kernel sessions require Administrator or Performance Log Users membership; offline/synthetic traces remain available".to_string()
    };

    AvailabilityReport {
        elevation,
        se_debug_available,
        etw_session_hint,
        windows_build: std::env::consts::OS.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn availability_report_does_not_require_elevation() {
        let report = check_availability();
        assert!(!report.etw_session_hint.is_empty());
        assert!(!report.elevation.integrity_level.is_empty());
    }
}
