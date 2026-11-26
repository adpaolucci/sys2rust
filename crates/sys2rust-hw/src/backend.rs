use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sys2rust_core::Sys2RustResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEntry {
    pub service_name: String,
    pub display_name: String,
    pub status: String,
    pub startup_type: String,
    pub service_type: String,
    pub binary_path: String,
    pub account: String,
    pub description: String,
    pub pid: u32,
    pub company: String,
    pub signed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverEntry {
    pub driver_name: String,
    pub address: u64,
    pub end_address: u64,
    pub size_bytes: u64,
    pub load_count: u32,
    pub driver_type: String,
    pub path: String,
    pub product_name: String,
    pub version: String,
    pub company: String,
    pub modified_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceEntry {
    pub device_name: String,
    pub device_type: String,
    pub status: String,
    pub connected: bool,
    pub problem_code: u32,
    pub hardware_id: String,
    pub driver_name: String,
    pub driver_version: String,
    pub manufacturer: String,
    pub instance_id: String,
    pub service_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskEntry {
    pub task_name: String,
    pub folder: String,
    pub status: String,
    pub enabled: bool,
    pub hidden: bool,
    pub triggers: String,
    pub actions: String,
    pub last_run_time: Option<DateTime<Utc>>,
    pub next_run_time: Option<DateTime<Utc>>,
    pub last_result: u32,
    pub wake_to_run: bool,
    pub run_as_user: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WmiRowEntry {
    pub namespace: String,
    pub class_name: String,
    pub instance_id: String,
    pub properties: BTreeMap<String, String>,
    pub timestamp_utc: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareTableEntry {
    pub provider_signature: String,
    pub table_id: String,
    pub length: u64,
    pub oem_id: String,
    pub oem_table_id: String,
    pub revision: u32,
    pub checksum_valid: bool,
    pub decoded_summary: String,
    #[serde(skip_serializing)]
    pub raw_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatteryEntry {
    pub battery_name: String,
    pub manufacturer: String,
    pub serial: String,
    pub chemistry: String,
    pub designed_capacity_mwh: u64,
    pub full_charged_capacity_mwh: u64,
    pub wear_level_pct: f64,
    pub current_capacity_mwh: u64,
    pub voltage_mv: u64,
    pub power_state: String,
    pub charge_rate_mw: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodecEntry {
    pub codec_name: String,
    pub codec_type: String,
    pub clsid: String,
    pub filename: String,
    pub merit: u32,
    pub disabled: bool,
    pub version: String,
    pub company: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeZoneEntry {
    pub time_zone_id: String,
    pub display_name: String,
    pub standard_name: String,
    pub daylight_name: String,
    pub utc_offset_min: i64,
    pub supports_dst: bool,
    pub current_local_time: DateTime<Utc>,
    pub dst_start_rule: String,
    pub dst_end_rule: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecialFolderEntry {
    pub folder_name: String,
    pub csidl: String,
    pub known_folder_guid: String,
    pub resolved_path: String,
    pub exists: bool,
    pub env_variable: String,
}

pub trait HwBackend: Send + Sync {
    fn list_services(&self) -> Sys2RustResult<Vec<ServiceEntry>>;
    fn list_drivers(&self) -> Sys2RustResult<Vec<DriverEntry>>;
    fn list_devices(&self) -> Sys2RustResult<Vec<DeviceEntry>>;
    fn list_tasks(&self) -> Sys2RustResult<Vec<TaskEntry>>;
    fn query_wmi(&self, namespace: &str, wql: &str) -> Sys2RustResult<Vec<WmiRowEntry>>;
    fn list_firmware_tables(&self) -> Sys2RustResult<Vec<FirmwareTableEntry>>;
    fn list_batteries(&self) -> Sys2RustResult<Vec<BatteryEntry>>;
    fn list_codecs(&self) -> Sys2RustResult<Vec<CodecEntry>>;
    fn list_timezones(&self) -> Sys2RustResult<Vec<TimeZoneEntry>>;
    fn list_special_folders(&self) -> Sys2RustResult<Vec<SpecialFolderEntry>>;

    // Mutating actions
    fn control_service(
        &self,
        service_name: &str,
        action: &str,
        startup_type: Option<&str>,
        dry_run: bool,
    ) -> Sys2RustResult<String>;
    fn control_device(&self, instance_id: &str, enable: bool, dry_run: bool) -> Sys2RustResult<String>;
    fn control_task(&self, task_path: &str, action: &str, dry_run: bool) -> Sys2RustResult<String>;
    fn control_codec(&self, codec_id: &str, enable: bool, dry_run: bool) -> Sys2RustResult<String>;
}
