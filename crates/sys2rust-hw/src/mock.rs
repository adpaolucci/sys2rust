use std::collections::BTreeMap;
use std::sync::Mutex;

use chrono::{TimeZone, Utc};
use sys2rust_core::binary::dmtf_to_datetime;
use sys2rust_core::{Sys2RustError, Sys2RustResult};

use crate::backend::{
    BatteryEntry, CodecEntry, DeviceEntry, DriverEntry, FirmwareTableEntry, HwBackend, ServiceEntry,
    SpecialFolderEntry, TaskEntry, TimeZoneEntry, WmiRowEntry,
};
use crate::parsers::{
    current_local_from_offset, decode_reg_tzi, finalize_acpi_checksum, parse_acpi_table, parse_smbios_raw_data,
    parse_system_ini_drivers32, parse_task_scheduler_xml,
};

#[derive(Debug, Default)]
struct MockHwState {
    services: Vec<ServiceEntry>,
    devices: Vec<DeviceEntry>,
    tasks: Vec<TaskEntry>,
    codecs: Vec<CodecEntry>,
    no_battery_hardware: bool,
}

pub struct MockHwBackend {
    state: Mutex<MockHwState>,
}

impl Default for MockHwBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MockHwBackend {
    pub fn new() -> Self {
        let services = vec![
            ServiceEntry {
                service_name: "wuauserv".to_string(),
                display_name: "Windows Update".to_string(),
                status: "Running".to_string(),
                startup_type: "Manual".to_string(),
                service_type: "ShareProcess".to_string(),
                binary_path: r"C:\Windows\system32\svchost.exe -k netsvcs -p".to_string(),
                account: "LocalSystem".to_string(),
                description: "Enables the detection, download, and installation of updates.".to_string(),
                pid: 1400,
                company: "Microsoft Corporation".to_string(),
                signed: true,
            },
            ServiceEntry {
                service_name: "Spooler".to_string(),
                display_name: "Print Spooler".to_string(),
                status: "Stopped".to_string(),
                startup_type: "Disabled".to_string(),
                service_type: "OwnProcess".to_string(),
                binary_path: r"C:\Windows\System32\spoolsv.exe".to_string(),
                account: "LocalSystem".to_string(),
                description: "Loads files to memory for later printing.".to_string(),
                pid: 0,
                company: "Microsoft Corporation".to_string(),
                signed: true,
            },
        ];

        let devices = vec![DeviceEntry {
            device_name: "NVIDIA GeForce RTX Virtual Adapter".to_string(),
            device_type: "Display".to_string(),
            status: "OK".to_string(),
            connected: true,
            problem_code: 0,
            hardware_id: r"PCI\VEN_10DE&DEV_2684".to_string(),
            driver_name: "nvlddmkm.sys".to_string(),
            driver_version: "32.0.15.6603".to_string(),
            manufacturer: "NVIDIA".to_string(),
            instance_id: r"PCI\VEN_10DE&DEV_2684\4&1234&0&0008".to_string(),
            service_name: "nvlddmkm".to_string(),
        }];

        let xml_utf8 = br#"<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Principals><Principal id="Author"><UserId>NT AUTHORITY\SYSTEM</UserId></Principal></Principals>
  <Triggers><CalendarTrigger><StartBoundary>2026-11-23T03:00:00Z</StartBoundary></CalendarTrigger></Triggers>
  <Settings><Enabled>true</Enabled><Hidden>false</Hidden><WakeToRun>true</WakeToRun></Settings>
  <Actions><Exec><Command>C:\Windows\System32\schtasks.exe</Command><Arguments>/Query</Arguments></Exec></Actions>
</Task>"#;

        let tasks = vec![parse_task_scheduler_xml(r"\Microsoft\Windows\Maintenance", "DailyAudit", xml_utf8).unwrap()];

        let ini = "[drivers32]\nVIDC.XVID=xvidvfw.dll\n;VIDC.OLD=disabled_codec.dll\n";
        let codecs = parse_system_ini_drivers32(ini);

        Self {
            state: Mutex::new(MockHwState {
                services,
                devices,
                tasks,
                codecs,
                no_battery_hardware: false,
            }),
        }
    }

    pub fn with_no_battery_hardware(self, no_battery: bool) -> Self {
        self.state.lock().unwrap().no_battery_hardware = no_battery;
        self
    }

    /// Build a deterministic synthetic `RawSMBIOSData` buffer with Types 0, 1, 2, 3, 4, 16, 17, 19, and 127.
    pub fn synthetic_smbios_bytes() -> Vec<u8> {
        let mut stream = Vec::new();
        let push_struct = |buf: &mut Vec<u8>, stype: u8, body: &[u8], strings: &[&str]| {
            let start = buf.len();
            buf.push(stype);
            buf.push((body.len() + 2) as u8);
            buf.extend_from_slice(body);
            if strings.is_empty() {
                buf.extend_from_slice(&[0, 0]);
            } else {
                for s in strings {
                    buf.extend_from_slice(s.as_bytes());
                    buf.push(0);
                }
                buf.push(0);
            }
            let _ = start;
        };

        // Type 0 BIOS Info (len 20 -> body 18)
        let mut t0 = vec![0u8; 18];
        t0[2] = 1; // Vendor idx 1
        t0[3] = 2; // Version idx 2
        t0[6] = 3; // Release Date idx 3
        t0[7] = 255; // 16 MiB ROM
        push_struct(&mut stream, 0, &t0, &["American Megatrends", "F12", "11/01/2026"]);

        // Type 1 System Info (len 27 -> body 25)
        let mut t1 = vec![0u8; 25];
        t1[2] = 1;
        t1[3] = 2;
        t1[6..22].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        push_struct(&mut stream, 1, &t1, &["GUAP Systems", "Workstation-X64"]);

        // Type 2 Baseboard
        let mut t2 = vec![0u8; 6];
        t2[2] = 1;
        t2[3] = 2;
        push_struct(&mut stream, 2, &t2, &["ASUSTeK", "PRO WS TRX50"]);

        // Type 3 Chassis
        let mut t3 = vec![0u8; 6];
        t3[2] = 1;
        t3[3] = 3; // Desktop
        push_struct(&mut stream, 3, &t3, &["Fractal Design"]);

        // Type 4 Processor
        let mut t4 = vec![0u8; 36];
        t4[2] = 1; // Socket
        t4[14] = 2; // Version
        t4[18..20].copy_from_slice(&4800u16.to_le_bytes()); // Max MHz
        t4[33] = 16; // Core count
        push_struct(&mut stream, 4, &t4, &["AM5", "AMD Ryzen 9 9950X"]);

        // Type 16 Physical Memory Array
        let mut t16 = vec![0u8; 13];
        t16[5..9].copy_from_slice(&(128 * 1024 * 1024u32).to_le_bytes());
        t16[11..13].copy_from_slice(&4u16.to_le_bytes());
        push_struct(&mut stream, 16, &t16, &[]);

        // Type 17 Memory Device (16384 MiB DDR5-5600)
        let mut t17 = vec![0u8; 26];
        t17[10..12].copy_from_slice(&16384u16.to_le_bytes());
        t17[14] = 1; // Locator
        t17[19..21].copy_from_slice(&5600u16.to_le_bytes());
        t17[21] = 2; // Manufacturer
        push_struct(&mut stream, 17, &t17, &["DIMM_A1", "G.Skill"]);

        // Type 19 Memory Array Mapped Address
        let mut t19 = vec![0u8; 11];
        t19[2..6].copy_from_slice(&0u32.to_le_bytes());
        t19[6..10].copy_from_slice(&(64 * 1024 * 1024u32).to_le_bytes());
        push_struct(&mut stream, 19, &t19, &[]);

        // Type 127 End of Table
        push_struct(&mut stream, 127, &[0, 0], &[]);

        let mut raw = vec![0, 3, 7, 0];
        raw.extend_from_slice(&(stream.len() as u32).to_le_bytes());
        raw.extend_from_slice(&stream);
        raw
    }

    /// Build synthetic ACPI `RSDT`, `FACP`, `DSDT`, `MCFG`, and `TPM2` buffers with valid checksums.
    pub fn synthetic_acpi_tables() -> Vec<Vec<u8>> {
        let make_sdt = |sig: &[u8; 4], rev: u8, payload: &[u8]| -> Vec<u8> {
            let total = 36 + payload.len();
            let mut b = vec![0u8; total];
            b[0..4].copy_from_slice(sig);
            b[4..8].copy_from_slice(&(total as u32).to_le_bytes());
            b[8] = rev;
            b[10..16].copy_from_slice(b"GUAP  ");
            b[16..24].copy_from_slice(b"SYS2RUST");
            b[36..].copy_from_slice(payload);
            finalize_acpi_checksum(&mut b);
            b
        };

        let rsdt = make_sdt(b"RSDT", 1, &[0, 0, 0, 0x10, 0, 0, 0, 0x20]);

        let mut facp_body = vec![0u8; 16];
        facp_body[0..4].copy_from_slice(&0x7000_0000u32.to_le_bytes());
        facp_body[4..8].copy_from_slice(&0x7000_1000u32.to_le_bytes());
        facp_body[9] = 1; // Desktop PM profile
        facp_body[10..12].copy_from_slice(&9u16.to_le_bytes());
        let facp = make_sdt(b"FACP", 6, &facp_body);

        let dsdt = make_sdt(b"DSDT", 2, b"\x10\x20\x30\x40\x50\x60");

        let mut mcfg_body = vec![0u8; 8 + 16];
        mcfg_body[8..16].copy_from_slice(&0xE000_0000u64.to_le_bytes());
        mcfg_body[16..18].copy_from_slice(&0u16.to_le_bytes());
        mcfg_body[18] = 0;
        mcfg_body[19] = 255;
        let mcfg = make_sdt(b"MCFG", 1, &mcfg_body);

        let mut tpm2_body = vec![0u8; 16];
        tpm2_body[0..2].copy_from_slice(&0u16.to_le_bytes());
        tpm2_body[4..12].copy_from_slice(&0xFED4_0040u64.to_le_bytes());
        tpm2_body[12..16].copy_from_slice(&7u32.to_le_bytes()); // CRB
        let tpm2 = make_sdt(b"TPM2", 4, &tpm2_body);

        vec![rsdt, facp, dsdt, mcfg, tpm2]
    }

    pub fn synthetic_eastern_tzi_bytes() -> [u8; 44] {
        let mut b = [0u8; 44];
        b[0..4].copy_from_slice(&300i32.to_le_bytes()); // Bias = 300 (UTC-5)
        b[4..8].copy_from_slice(&0i32.to_le_bytes()); // StandardBias = 0
        b[8..12].copy_from_slice(&(-60i32).to_le_bytes()); // DaylightBias = -60
        // StandardDate at +12: November (11), Sunday (0), 1st (1), 02:00
        b[14..16].copy_from_slice(&11u16.to_le_bytes());
        b[16..18].copy_from_slice(&0u16.to_le_bytes());
        b[18..20].copy_from_slice(&1u16.to_le_bytes());
        b[20..22].copy_from_slice(&2u16.to_le_bytes());
        // DaylightDate at +28: March (3), Sunday (0), 2nd (2), 02:00
        b[30..32].copy_from_slice(&3u16.to_le_bytes());
        b[32..34].copy_from_slice(&0u16.to_le_bytes());
        b[34..36].copy_from_slice(&2u16.to_le_bytes());
        b[36..38].copy_from_slice(&2u16.to_le_bytes());
        b
    }
}

impl HwBackend for MockHwBackend {
    fn list_services(&self) -> Sys2RustResult<Vec<ServiceEntry>> {
        Ok(self.state.lock().unwrap().services.clone())
    }

    fn list_drivers(&self) -> Sys2RustResult<Vec<DriverEntry>> {
        let ts = Utc.with_ymd_and_hms(2026, 11, 20, 12, 0, 0).unwrap();
        Ok(vec![DriverEntry {
            driver_name: "ntoskrnl.exe".to_string(),
            address: 0xFFFF_F800_1000_0000,
            end_address: 0xFFFF_F800_1100_0000,
            size_bytes: 16_777_216,
            load_count: 1,
            driver_type: "Kernel".to_string(),
            path: r"C:\Windows\System32\ntoskrnl.exe".to_string(),
            product_name: "Microsoft Windows Operating System".to_string(),
            version: "10.0.26300.1".to_string(),
            company: "Microsoft Corporation".to_string(),
            modified_time: Some(ts),
        }])
    }

    fn list_devices(&self) -> Sys2RustResult<Vec<DeviceEntry>> {
        Ok(self.state.lock().unwrap().devices.clone())
    }

    fn list_tasks(&self) -> Sys2RustResult<Vec<TaskEntry>> {
        Ok(self.state.lock().unwrap().tasks.clone())
    }

    fn query_wmi(&self, namespace: &str, _wql: &str) -> Sys2RustResult<Vec<WmiRowEntry>> {
        let mut props = BTreeMap::new();
        props.insert("Caption".to_string(), "Microsoft Windows 11 Pro".to_string());
        props.insert("BuildNumber".to_string(), "26300".to_string());
        props.insert("OSArchitecture".to_string(), "64-bit".to_string());
        props.insert("LastBootUpTime".to_string(), "20261123020000.000000+000".to_string());
        Ok(vec![WmiRowEntry {
            namespace: namespace.to_string(),
            class_name: "Win32_OperatingSystem".to_string(),
            instance_id: "Workstation-OS".to_string(),
            properties: props,
            timestamp_utc: dmtf_to_datetime("20261123020000.000000+000"),
        }])
    }

    fn list_firmware_tables(&self) -> Sys2RustResult<Vec<FirmwareTableEntry>> {
        let mut out = vec![parse_smbios_raw_data(&Self::synthetic_smbios_bytes())?];
        for tbl in Self::synthetic_acpi_tables() {
            out.push(parse_acpi_table(&tbl)?);
        }
        Ok(out)
    }

    fn list_batteries(&self) -> Sys2RustResult<Vec<BatteryEntry>> {
        if self.state.lock().unwrap().no_battery_hardware {
            return Err(Sys2RustError::HardwareNotFound {
                device: "Battery",
                detail: "No smart battery device interface found (desktop workstation)".to_string(),
            });
        }
        let design = 60_000u64;
        let full = 51_000u64;
        let wear = ((design - full) as f64 / design as f64) * 100.0;
        Ok(vec![BatteryEntry {
            battery_name: "Primary Smart Battery".to_string(),
            manufacturer: "SMP".to_string(),
            serial: "BAT-2026-001".to_string(),
            chemistry: "LIon".to_string(),
            designed_capacity_mwh: design,
            full_charged_capacity_mwh: full,
            wear_level_pct: wear,
            current_capacity_mwh: 42_500,
            voltage_mv: 12_450,
            power_state: "AC Online / Charging".to_string(),
            charge_rate_mw: 18_500,
        }])
    }

    fn list_codecs(&self) -> Sys2RustResult<Vec<CodecEntry>> {
        Ok(self.state.lock().unwrap().codecs.clone())
    }

    fn list_timezones(&self) -> Sys2RustResult<Vec<TimeZoneEntry>> {
        let tzi = decode_reg_tzi(&Self::synthetic_eastern_tzi_bytes())?;
        let now = Utc.with_ymd_and_hms(2026, 11, 23, 4, 0, 0).unwrap();
        Ok(vec![TimeZoneEntry {
            time_zone_id: "Eastern Standard Time".to_string(),
            display_name: "(UTC-05:00) Eastern Time (US & Canada)".to_string(),
            standard_name: "Eastern Standard Time".to_string(),
            daylight_name: "Eastern Daylight Time".to_string(),
            utc_offset_min: tzi.utc_offset_min,
            supports_dst: tzi.supports_dst,
            current_local_time: current_local_from_offset(now, tzi.utc_offset_min),
            dst_start_rule: tzi.dst_start_rule,
            dst_end_rule: tzi.dst_end_rule,
        }])
    }

    fn list_special_folders(&self) -> Sys2RustResult<Vec<SpecialFolderEntry>> {
        Ok(vec![
            SpecialFolderEntry {
                folder_name: "Desktop".to_string(),
                csidl: "CSIDL_DESKTOPDIRECTORY (0x0010)".to_string(),
                known_folder_guid: "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}".to_string(),
                resolved_path: r"C:\Users\User\Desktop".to_string(),
                exists: true,
                env_variable: "%USERPROFILE%\\Desktop".to_string(),
            },
            SpecialFolderEntry {
                folder_name: "System32".to_string(),
                csidl: "CSIDL_SYSTEM (0x0025)".to_string(),
                known_folder_guid: "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}".to_string(),
                resolved_path: r"C:\Windows\System32".to_string(),
                exists: true,
                env_variable: "%WINDIR%\\System32".to_string(),
            },
        ])
    }

    fn control_service(
        &self,
        service_name: &str,
        action: &str,
        startup_type: Option<&str>,
        dry_run: bool,
    ) -> Sys2RustResult<String> {
        let mut st = self.state.lock().unwrap();
        let Some(svc) = st
            .services
            .iter_mut()
            .find(|s| s.service_name.eq_ignore_ascii_case(service_name))
        else {
            return Err(Sys2RustError::NotFound(format!("service '{service_name}'")));
        };
        if dry_run {
            return Ok(format!("[dry-run] would apply '{action}' to service '{service_name}'"));
        }
        match action {
            "start" => svc.status = "Running".to_string(),
            "stop" => svc.status = "Stopped".to_string(),
            "pause" => svc.status = "Paused".to_string(),
            "resume" => svc.status = "Running".to_string(),
            "set_startup" => {
                svc.startup_type = startup_type.unwrap_or("Manual").to_string();
            }
            other => return Err(Sys2RustError::InvalidArgument(format!("unknown action '{other}'"))),
        }
        Ok(format!("service '{service_name}' updated ({action})"))
    }

    fn control_device(&self, instance_id: &str, enable: bool, dry_run: bool) -> Sys2RustResult<String> {
        let mut st = self.state.lock().unwrap();
        let Some(dev) = st
            .devices
            .iter_mut()
            .find(|d| d.instance_id.eq_ignore_ascii_case(instance_id))
        else {
            return Err(Sys2RustError::NotFound(format!("device '{instance_id}'")));
        };
        let verb = if enable { "enable" } else { "disable" };
        if dry_run {
            return Ok(format!("[dry-run] would {verb} device '{instance_id}'"));
        }
        dev.connected = enable;
        dev.status = if enable { "OK" } else { "Disabled" }.to_string();
        Ok(format!("device '{instance_id}' {verb}d"))
    }

    fn control_task(&self, task_path: &str, action: &str, dry_run: bool) -> Sys2RustResult<String> {
        let mut st = self.state.lock().unwrap();
        let Some(task) = st.tasks.iter_mut().find(|t| {
            t.task_name.eq_ignore_ascii_case(task_path)
                || format!("{}\\{}", t.folder, t.task_name).eq_ignore_ascii_case(task_path)
        }) else {
            return Err(Sys2RustError::NotFound(format!("task '{task_path}'")));
        };
        if dry_run {
            return Ok(format!("[dry-run] would {action} task '{task_path}'"));
        }
        match action {
            "enable" => {
                task.enabled = true;
                task.status = "Ready".to_string();
            }
            "disable" => {
                task.enabled = false;
                task.status = "Disabled".to_string();
            }
            "run" => {
                task.last_run_time = Some(Utc::now());
            }
            other => return Err(Sys2RustError::InvalidArgument(format!("unknown task action '{other}'"))),
        }
        Ok(format!("task '{task_path}' {action} completed"))
    }

    fn control_codec(&self, codec_id: &str, enable: bool, dry_run: bool) -> Sys2RustResult<String> {
        let mut st = self.state.lock().unwrap();
        let Some(codec) = st
            .codecs
            .iter_mut()
            .find(|c| c.codec_name.eq_ignore_ascii_case(codec_id) || c.clsid.eq_ignore_ascii_case(codec_id))
        else {
            return Err(Sys2RustError::NotFound(format!("codec '{codec_id}'")));
        };
        let verb = if enable { "enable" } else { "disable" };
        if dry_run {
            return Ok(format!("[dry-run] would {verb} codec '{codec_id}'"));
        }
        codec.disabled = !enable;
        Ok(format!("codec '{codec_id}' {verb}d"))
    }
}
