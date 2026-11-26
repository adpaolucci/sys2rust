use std::sync::Arc;

use guap_mcp::{ActionCommand, ActionRiskLevel, McpToolError};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, TableData, TableError, TableProvider, TableQuery, TableSchema, apply_query,
};
use serde_json::{Value, json};
use sys2rust_core::Sys2RustConfig;

use crate::backend::HwBackend;

pub fn all_hw_providers(backend: Arc<dyn HwBackend>, cfg: Sys2RustConfig) -> Vec<Arc<dyn TableProvider>> {
    vec![
        Arc::new(HwServicesProvider::new(Arc::clone(&backend))),
        Arc::new(HwDriversProvider::new(Arc::clone(&backend))),
        Arc::new(HwDevicesProvider::new(Arc::clone(&backend))),
        Arc::new(HwTasksProvider::new(Arc::clone(&backend))),
        Arc::new(HwWmiProvider::new(Arc::clone(&backend), cfg)),
        Arc::new(HwFirmwareProvider::new(Arc::clone(&backend))),
        Arc::new(HwBatteryProvider::new(Arc::clone(&backend))),
        Arc::new(HwCodecsProvider::new(Arc::clone(&backend))),
        Arc::new(HwTimeZonesProvider::new(Arc::clone(&backend))),
        Arc::new(HwSpecialFoldersProvider::new(backend)),
    ]
}

pub fn all_hw_actions(backend: Arc<dyn HwBackend>) -> Vec<Arc<dyn ActionCommand>> {
    vec![
        Arc::new(HwServiceControlAction {
            backend: Arc::clone(&backend),
        }),
        Arc::new(HwDeviceControlAction {
            backend: Arc::clone(&backend),
        }),
        Arc::new(HwTaskControlAction {
            backend: Arc::clone(&backend),
        }),
        Arc::new(HwCodecControlAction { backend }),
    ]
}

fn hex_u64(v: u64) -> CellValue {
    CellValue::Hex(v.to_be_bytes().to_vec())
}

// 1. hw_services (ServiWin)
pub struct HwServicesProvider {
    backend: Arc<dyn HwBackend>,
}
impl HwServicesProvider {
    pub fn new(backend: Arc<dyn HwBackend>) -> Self {
        Self { backend }
    }
}
impl TableProvider for HwServicesProvider {
    fn tool_id(&self) -> &'static str {
        "hw_services"
    }
    fn description(&self) -> &'static str {
        "Inspect Windows services, status, startup type, binary path, and account (ServiWin)"
    }
    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Windows Services (ServiWin)",
            vec![
                ColumnDef::new("service_name", "Service Name", ColumnType::Text).with_width_hint(150),
                ColumnDef::new("display_name", "Display Name", ColumnType::Text).with_width_hint(200),
                ColumnDef::new("status", "Status", ColumnType::Text).with_width_hint(90),
                ColumnDef::new("startup_type", "Startup", ColumnType::Text).with_width_hint(90),
                ColumnDef::new("service_type", "Type", ColumnType::Text).with_width_hint(100),
                ColumnDef::new("binary_path", "Binary Path", ColumnType::Text).with_width_hint(240),
                ColumnDef::new("account", "Account", ColumnType::Text).with_width_hint(130),
                ColumnDef::new("description", "Description", ColumnType::Text).with_width_hint(220),
                ColumnDef::new("pid", "PID", ColumnType::Uint).with_width_hint(75),
                ColumnDef::new("company", "Company", ColumnType::Text).with_width_hint(140),
                ColumnDef::new("signed", "Signed", ColumnType::Bool).with_width_hint(70),
            ],
        )
    }
    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let items = self.backend.list_services()?;
        let rows: Vec<Row> = items
            .into_iter()
            .enumerate()
            .map(|(i, s)| {
                Row::new(
                    (i + 1) as u64,
                    vec![
                        CellValue::Text(s.service_name.clone()),
                        CellValue::Text(s.display_name.clone()),
                        CellValue::Text(s.status.clone()),
                        CellValue::Text(s.startup_type.clone()),
                        CellValue::Text(s.service_type.clone()),
                        CellValue::Text(s.binary_path.clone()),
                        CellValue::Text(s.account.clone()),
                        CellValue::Text(s.description.clone()),
                        CellValue::Uint(u64::from(s.pid)),
                        CellValue::Text(s.company.clone()),
                        CellValue::Bool(s.signed),
                    ],
                )
                .with_detail_json(json!(s))
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}

// 2. hw_drivers (DriverView)
pub struct HwDriversProvider {
    backend: Arc<dyn HwBackend>,
}
impl HwDriversProvider {
    pub fn new(backend: Arc<dyn HwBackend>) -> Self {
        Self { backend }
    }
}
impl TableProvider for HwDriversProvider {
    fn tool_id(&self) -> &'static str {
        "hw_drivers"
    }
    fn description(&self) -> &'static str {
        "Inspect loaded kernel-mode device drivers and base addresses (DriverView)"
    }
    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Loaded Kernel Drivers (DriverView)",
            vec![
                ColumnDef::new("driver_name", "Driver Name", ColumnType::Text).with_width_hint(150),
                ColumnDef::new("address", "Base Address", ColumnType::Hex).with_width_hint(140),
                ColumnDef::new("end_address", "End Address", ColumnType::Hex).with_width_hint(140),
                ColumnDef::new("size", "Size", ColumnType::BytesSize).with_width_hint(100),
                ColumnDef::new("load_count", "Load Count", ColumnType::Uint).with_width_hint(85),
                ColumnDef::new("driver_type", "Type", ColumnType::Text).with_width_hint(90),
                ColumnDef::new("path", "Path", ColumnType::Text).with_width_hint(240),
                ColumnDef::new("product_name", "Product Name", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("version", "Version", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("company", "Company", ColumnType::Text).with_width_hint(140),
                ColumnDef::new("modified_time", "Modified", ColumnType::Timestamp).with_width_hint(170),
            ],
        )
    }
    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let items = self.backend.list_drivers()?;
        let rows: Vec<Row> = items
            .into_iter()
            .enumerate()
            .map(|(i, d)| {
                Row::new(
                    (i + 1) as u64,
                    vec![
                        CellValue::Text(d.driver_name.clone()),
                        hex_u64(d.address),
                        hex_u64(d.end_address),
                        CellValue::Bytes(d.size_bytes),
                        CellValue::Uint(u64::from(d.load_count)),
                        CellValue::Text(d.driver_type.clone()),
                        CellValue::Text(d.path.clone()),
                        CellValue::Text(d.product_name.clone()),
                        CellValue::Text(d.version.clone()),
                        CellValue::Text(d.company.clone()),
                        d.modified_time.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                    ],
                )
                .with_detail_json(json!(d))
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}

// 3. hw_devices (DevManView)
pub struct HwDevicesProvider {
    backend: Arc<dyn HwBackend>,
}
impl HwDevicesProvider {
    pub fn new(backend: Arc<dyn HwBackend>) -> Self {
        Self { backend }
    }
}
impl TableProvider for HwDevicesProvider {
    fn tool_id(&self) -> &'static str {
        "hw_devices"
    }
    fn description(&self) -> &'static str {
        "Inspect PnP devices, status, problem codes, hardware IDs, and drivers (DevManView)"
    }
    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "PnP Device Manager (DevManView)",
            vec![
                ColumnDef::new("device_name", "Device Name", ColumnType::Text).with_width_hint(220),
                ColumnDef::new("device_type", "Class", ColumnType::Text).with_width_hint(120),
                ColumnDef::new("status", "Status", ColumnType::Text).with_width_hint(90),
                ColumnDef::new("connected", "Connected", ColumnType::Bool).with_width_hint(80),
                ColumnDef::new("problem_code", "Problem", ColumnType::Uint).with_width_hint(75),
                ColumnDef::new("hardware_id", "Hardware ID", ColumnType::Text).with_width_hint(200),
                ColumnDef::new("driver_name", "Driver", ColumnType::Text).with_width_hint(120),
                ColumnDef::new("driver_version", "Version", ColumnType::Text).with_width_hint(100),
                ColumnDef::new("manufacturer", "Manufacturer", ColumnType::Text).with_width_hint(140),
                ColumnDef::new("instance_id", "Instance ID", ColumnType::Text).with_width_hint(230),
                ColumnDef::new("service_name", "Service", ColumnType::Text).with_width_hint(110),
            ],
        )
    }
    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let items = self.backend.list_devices()?;
        let rows: Vec<Row> = items
            .into_iter()
            .enumerate()
            .map(|(i, d)| {
                Row::new(
                    (i + 1) as u64,
                    vec![
                        CellValue::Text(d.device_name.clone()),
                        CellValue::Text(d.device_type.clone()),
                        CellValue::Text(d.status.clone()),
                        CellValue::Bool(d.connected),
                        CellValue::Uint(u64::from(d.problem_code)),
                        CellValue::Text(d.hardware_id.clone()),
                        CellValue::Text(d.driver_name.clone()),
                        CellValue::Text(d.driver_version.clone()),
                        CellValue::Text(d.manufacturer.clone()),
                        CellValue::Text(d.instance_id.clone()),
                        CellValue::Text(d.service_name.clone()),
                    ],
                )
                .with_detail_json(json!(d))
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}

// 4. hw_tasks (TaskSchedulerView)
pub struct HwTasksProvider {
    backend: Arc<dyn HwBackend>,
}
impl HwTasksProvider {
    pub fn new(backend: Arc<dyn HwBackend>) -> Self {
        Self { backend }
    }
}
impl TableProvider for HwTasksProvider {
    fn tool_id(&self) -> &'static str {
        "hw_tasks"
    }
    fn description(&self) -> &'static str {
        "Inspect Windows Scheduled Tasks via TaskScheduler COM and Task XML parser (TaskSchedulerView)"
    }
    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Scheduled Tasks (TaskSchedulerView)",
            vec![
                ColumnDef::new("task_name", "Task Name", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("folder", "Folder", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("status", "Status", ColumnType::Text).with_width_hint(90),
                ColumnDef::new("enabled", "Enabled", ColumnType::Bool).with_width_hint(70),
                ColumnDef::new("hidden", "Hidden", ColumnType::Bool).with_width_hint(70),
                ColumnDef::new("triggers", "Triggers", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("actions", "Actions", ColumnType::Text).with_width_hint(220),
                ColumnDef::new("last_run_time", "Last Run", ColumnType::Timestamp).with_width_hint(170),
                ColumnDef::new("next_run_time", "Next Run", ColumnType::Timestamp).with_width_hint(170),
                ColumnDef::new("last_result", "Last Result", ColumnType::Hex).with_width_hint(95),
                ColumnDef::new("wake_to_run", "Wake", ColumnType::Bool).with_width_hint(65),
                ColumnDef::new("run_as_user", "Run As", ColumnType::Text).with_width_hint(150),
            ],
        )
    }
    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let items = self.backend.list_tasks()?;
        let rows: Vec<Row> = items
            .into_iter()
            .enumerate()
            .map(|(i, t)| {
                Row::new(
                    (i + 1) as u64,
                    vec![
                        CellValue::Text(t.task_name.clone()),
                        CellValue::Text(t.folder.clone()),
                        CellValue::Text(t.status.clone()),
                        CellValue::Bool(t.enabled),
                        CellValue::Bool(t.hidden),
                        CellValue::Text(t.triggers.clone()),
                        CellValue::Text(t.actions.clone()),
                        t.last_run_time.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                        t.next_run_time.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                        CellValue::Hex(t.last_result.to_be_bytes().to_vec()),
                        CellValue::Bool(t.wake_to_run),
                        CellValue::Text(t.run_as_user.clone()),
                    ],
                )
                .with_detail_json(json!(t))
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}

// 5. hw_wmi (SimpleWMIView)
pub struct HwWmiProvider {
    backend: Arc<dyn HwBackend>,
    cfg: Sys2RustConfig,
}
impl HwWmiProvider {
    pub fn new(backend: Arc<dyn HwBackend>, cfg: Sys2RustConfig) -> Self {
        Self { backend, cfg }
    }
}
impl TableProvider for HwWmiProvider {
    fn tool_id(&self) -> &'static str {
        "hw_wmi"
    }
    fn description(&self) -> &'static str {
        "Execute WQL queries against WMI namespaces with SAFEARRAY & DMTF handling (SimpleWMIView)"
    }
    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "WMI Query Results (SimpleWMIView)",
            vec![
                ColumnDef::new("namespace", "Namespace", ColumnType::Text).with_width_hint(120),
                ColumnDef::new("class_name", "Class", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("instance_id", "Instance", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("properties", "Properties", ColumnType::Text).with_width_hint(360),
                ColumnDef::new("timestamp_utc", "DMTF Timestamp", ColumnType::Timestamp).with_width_hint(170),
            ],
        )
    }
    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let items = self.backend.query_wmi(&self.cfg.wmi_namespace, &self.cfg.wmi_query)?;
        let rows: Vec<Row> = items
            .into_iter()
            .enumerate()
            .map(|(i, w)| {
                let summary = w
                    .properties
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join("; ");
                Row::new(
                    (i + 1) as u64,
                    vec![
                        CellValue::Text(w.namespace.clone()),
                        CellValue::Text(w.class_name.clone()),
                        CellValue::Text(w.instance_id.clone()),
                        CellValue::Text(summary),
                        w.timestamp_utc.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                    ],
                )
                .with_detail_json(json!(w))
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}

// 6. hw_firmware (FirmwareTablesView)
pub struct HwFirmwareProvider {
    backend: Arc<dyn HwBackend>,
}
impl HwFirmwareProvider {
    pub fn new(backend: Arc<dyn HwBackend>) -> Self {
        Self { backend }
    }
}
impl TableProvider for HwFirmwareProvider {
    fn tool_id(&self) -> &'static str {
        "hw_firmware"
    }
    fn description(&self) -> &'static str {
        "Inspect and decode SMBIOS and ACPI firmware tables with checksum validation (FirmwareTablesView)"
    }
    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Firmware Tables: SMBIOS & ACPI (FirmwareTablesView)",
            vec![
                ColumnDef::new("provider_signature", "Provider", ColumnType::Text).with_width_hint(80),
                ColumnDef::new("table_id", "Table ID", ColumnType::Text).with_width_hint(90),
                ColumnDef::new("length", "Length", ColumnType::BytesSize).with_width_hint(95),
                ColumnDef::new("oem_id", "OEM ID", ColumnType::Text).with_width_hint(90),
                ColumnDef::new("oem_table_id", "OEM Table ID", ColumnType::Text).with_width_hint(120),
                ColumnDef::new("revision", "Revision", ColumnType::Uint).with_width_hint(75),
                ColumnDef::new("checksum_valid", "Checksum OK", ColumnType::Bool).with_width_hint(95),
                ColumnDef::new("decoded_summary", "Decoded Summary", ColumnType::Text).with_width_hint(360),
            ],
        )
    }
    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let items = self.backend.list_firmware_tables()?;
        let rows: Vec<Row> = items
            .into_iter()
            .enumerate()
            .map(|(i, f)| {
                Row::new(
                    (i + 1) as u64,
                    vec![
                        CellValue::Text(f.provider_signature.clone()),
                        CellValue::Text(f.table_id.clone()),
                        CellValue::Bytes(f.length),
                        CellValue::Text(f.oem_id.clone()),
                        CellValue::Text(f.oem_table_id.clone()),
                        CellValue::Uint(u64::from(f.revision)),
                        CellValue::Bool(f.checksum_valid),
                        CellValue::Text(f.decoded_summary.clone()),
                    ],
                )
                .with_detail_json(json!(f))
                .with_raw_bytes(f.raw_bytes)
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}

// 7. hw_battery (BatteryInfoView)
pub struct HwBatteryProvider {
    backend: Arc<dyn HwBackend>,
}
impl HwBatteryProvider {
    pub fn new(backend: Arc<dyn HwBackend>) -> Self {
        Self { backend }
    }
}
impl TableProvider for HwBatteryProvider {
    fn tool_id(&self) -> &'static str {
        "hw_battery"
    }
    fn description(&self) -> &'static str {
        "Inspect smart battery capacities, wear level, voltage, and charge rate via IOCTL_BATTERY (BatteryInfoView)"
    }
    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Smart Battery Diagnostics (BatteryInfoView)",
            vec![
                ColumnDef::new("battery_name", "Battery", ColumnType::Text).with_width_hint(140),
                ColumnDef::new("manufacturer", "Manufacturer", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("serial", "Serial", ColumnType::Text).with_width_hint(120),
                ColumnDef::new("chemistry", "Chemistry", ColumnType::Text).with_width_hint(85),
                ColumnDef::new("designed_capacity_mwh", "Design (mWh)", ColumnType::Uint).with_width_hint(105),
                ColumnDef::new("full_charged_capacity_mwh", "Full Charge (mWh)", ColumnType::Uint).with_width_hint(125),
                ColumnDef::new("wear_level_pct", "Wear (%)", ColumnType::Float).with_width_hint(85),
                ColumnDef::new("current_capacity_mwh", "Current (mWh)", ColumnType::Uint).with_width_hint(110),
                ColumnDef::new("voltage_mv", "Voltage (mV)", ColumnType::Uint).with_width_hint(100),
                ColumnDef::new("power_state", "Power State", ColumnType::Text).with_width_hint(140),
                ColumnDef::new("charge_rate_mw", "Rate (mW)", ColumnType::Int).with_width_hint(90),
            ],
        )
    }
    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let items = self.backend.list_batteries()?;
        let rows: Vec<Row> = items
            .into_iter()
            .enumerate()
            .map(|(i, b)| {
                Row::new(
                    (i + 1) as u64,
                    vec![
                        CellValue::Text(b.battery_name.clone()),
                        CellValue::Text(b.manufacturer.clone()),
                        CellValue::Text(b.serial.clone()),
                        CellValue::Text(b.chemistry.clone()),
                        CellValue::Uint(b.designed_capacity_mwh),
                        CellValue::Uint(b.full_charged_capacity_mwh),
                        CellValue::Float(b.wear_level_pct),
                        CellValue::Uint(b.current_capacity_mwh),
                        CellValue::Uint(b.voltage_mv),
                        CellValue::Text(b.power_state.clone()),
                        CellValue::Int(b.charge_rate_mw),
                    ],
                )
                .with_detail_json(json!(b))
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}

// 8. hw_codecs (InstalledCodec)
pub struct HwCodecsProvider {
    backend: Arc<dyn HwBackend>,
}
impl HwCodecsProvider {
    pub fn new(backend: Arc<dyn HwBackend>) -> Self {
        Self { backend }
    }
}
impl TableProvider for HwCodecsProvider {
    fn tool_id(&self) -> &'static str {
        "hw_codecs"
    }
    fn description(&self) -> &'static str {
        "Inspect installed MFT, Drivers32, and SYSTEM.INI audio/video codecs (InstalledCodec)"
    }
    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Installed Audio/Video Codecs (InstalledCodec)",
            vec![
                ColumnDef::new("codec_name", "Codec Name", ColumnType::Text).with_width_hint(200),
                ColumnDef::new("codec_type", "Type", ColumnType::Text).with_width_hint(140),
                ColumnDef::new("clsid", "CLSID", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("filename", "Filename", ColumnType::Text).with_width_hint(200),
                ColumnDef::new("merit", "Merit", ColumnType::Hex).with_width_hint(90),
                ColumnDef::new("disabled", "Disabled", ColumnType::Bool).with_width_hint(75),
                ColumnDef::new("version", "Version", ColumnType::Text).with_width_hint(100),
                ColumnDef::new("company", "Company", ColumnType::Text).with_width_hint(140),
            ],
        )
    }
    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let items = self.backend.list_codecs()?;
        let rows: Vec<Row> = items
            .into_iter()
            .enumerate()
            .map(|(i, c)| {
                Row::new(
                    (i + 1) as u64,
                    vec![
                        CellValue::Text(c.codec_name.clone()),
                        CellValue::Text(c.codec_type.clone()),
                        CellValue::Text(c.clsid.clone()),
                        CellValue::Text(c.filename.clone()),
                        CellValue::Hex(c.merit.to_be_bytes().to_vec()),
                        CellValue::Bool(c.disabled),
                        CellValue::Text(c.version.clone()),
                        CellValue::Text(c.company.clone()),
                    ],
                )
                .with_detail_json(json!(c))
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}

// 9. hw_timezones (TimeZonesView)
pub struct HwTimeZonesProvider {
    backend: Arc<dyn HwBackend>,
}
impl HwTimeZonesProvider {
    pub fn new(backend: Arc<dyn HwBackend>) -> Self {
        Self { backend }
    }
}
impl TableProvider for HwTimeZonesProvider {
    fn tool_id(&self) -> &'static str {
        "hw_timezones"
    }
    fn description(&self) -> &'static str {
        "Inspect Windows time zones, REG_TZI_FORMAT biases, and DST rules (TimeZonesView)"
    }
    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Windows Time Zones (TimeZonesView)",
            vec![
                ColumnDef::new("time_zone_id", "Time Zone ID", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("display_name", "Display Name", ColumnType::Text).with_width_hint(240),
                ColumnDef::new("standard_name", "Standard Name", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("daylight_name", "Daylight Name", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("utc_offset_min", "UTC Offset (min)", ColumnType::Int).with_width_hint(110),
                ColumnDef::new("supports_dst", "DST", ColumnType::Bool).with_width_hint(65),
                ColumnDef::new("current_local_time", "Local Time", ColumnType::Timestamp).with_width_hint(170),
                ColumnDef::new("dst_start_rule", "DST Start", ColumnType::Text).with_width_hint(130),
                ColumnDef::new("dst_end_rule", "DST End", ColumnType::Text).with_width_hint(130),
            ],
        )
    }
    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let items = self.backend.list_timezones()?;
        let rows: Vec<Row> = items
            .into_iter()
            .enumerate()
            .map(|(i, tz)| {
                Row::new(
                    (i + 1) as u64,
                    vec![
                        CellValue::Text(tz.time_zone_id.clone()),
                        CellValue::Text(tz.display_name.clone()),
                        CellValue::Text(tz.standard_name.clone()),
                        CellValue::Text(tz.daylight_name.clone()),
                        CellValue::Int(tz.utc_offset_min),
                        CellValue::Bool(tz.supports_dst),
                        CellValue::Timestamp(tz.current_local_time),
                        CellValue::Text(tz.dst_start_rule.clone()),
                        CellValue::Text(tz.dst_end_rule.clone()),
                    ],
                )
                .with_detail_json(json!(tz))
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}

// 10. hw_special_folders (SpecialFoldersView)
pub struct HwSpecialFoldersProvider {
    backend: Arc<dyn HwBackend>,
}
impl HwSpecialFoldersProvider {
    pub fn new(backend: Arc<dyn HwBackend>) -> Self {
        Self { backend }
    }
}
impl TableProvider for HwSpecialFoldersProvider {
    fn tool_id(&self) -> &'static str {
        "hw_special_folders"
    }
    fn description(&self) -> &'static str {
        "Resolve Windows Known Folders (FOLDERID_*) and CSIDL paths (SpecialFoldersView)"
    }
    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Special & Known Folders (SpecialFoldersView)",
            vec![
                ColumnDef::new("folder_name", "Folder Name", ColumnType::Text).with_width_hint(150),
                ColumnDef::new("csidl", "CSIDL", ColumnType::Text).with_width_hint(170),
                ColumnDef::new("known_folder_guid", "FOLDERID GUID", ColumnType::Text).with_width_hint(240),
                ColumnDef::new("resolved_path", "Resolved Path", ColumnType::Text).with_width_hint(260),
                ColumnDef::new("exists", "Exists", ColumnType::Bool).with_width_hint(70),
                ColumnDef::new("env_variable", "Env Pattern", ColumnType::Text).with_width_hint(200),
            ],
        )
    }
    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let items = self.backend.list_special_folders()?;
        let rows: Vec<Row> = items
            .into_iter()
            .enumerate()
            .map(|(i, f)| {
                Row::new(
                    (i + 1) as u64,
                    vec![
                        CellValue::Text(f.folder_name.clone()),
                        CellValue::Text(f.csidl.clone()),
                        CellValue::Text(f.known_folder_guid.clone()),
                        CellValue::Text(f.resolved_path.clone()),
                        CellValue::Bool(f.exists),
                        CellValue::Text(f.env_variable.clone()),
                    ],
                )
                .with_detail_json(json!(f))
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}

// --- Mutating ActionCommands ---

pub struct HwServiceControlAction {
    backend: Arc<dyn HwBackend>,
}
impl ActionCommand for HwServiceControlAction {
    fn command_id(&self) -> &'static str {
        "hw_service_control"
    }
    fn description(&self) -> &'static str {
        "Start, stop, pause, resume, or configure startup type of a Windows service"
    }
    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::PrivilegedMutating
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "service_name": { "type": "string" },
                "action": { "type": "string", "enum": ["start", "stop", "pause", "resume", "set_startup"] },
                "startup_type": { "type": "string", "enum": ["Auto", "Manual", "Disabled"] }
            },
            "required": ["service_name", "action"],
            "additionalProperties": false
        })
    }
    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let svc = args
            .get("service_name")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing 'service_name'".to_string()))?;
        let action = args
            .get("action")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing 'action'".to_string()))?;
        let startup = args.get("startup_type").and_then(Value::as_str);
        let msg = self.backend.control_service(svc, action, startup, dry_run)?;
        Ok(json!({ "status": "ok", "dry_run": dry_run, "message": msg }))
    }
}

pub struct HwDeviceControlAction {
    backend: Arc<dyn HwBackend>,
}
impl ActionCommand for HwDeviceControlAction {
    fn command_id(&self) -> &'static str {
        "hw_device_control"
    }
    fn description(&self) -> &'static str {
        "Enable or disable a PnP device via SetupDiSetClassInstallParamsW(DIF_PROPERTYCHANGE)"
    }
    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::PrivilegedMutating
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "instance_id": { "type": "string" },
                "enable": { "type": "boolean" }
            },
            "required": ["instance_id", "enable"],
            "additionalProperties": false
        })
    }
    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let id = args
            .get("instance_id")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing 'instance_id'".to_string()))?;
        let enable = args
            .get("enable")
            .and_then(Value::as_bool)
            .ok_or_else(|| McpToolError::InvalidParams("missing boolean 'enable'".to_string()))?;
        let msg = self.backend.control_device(id, enable, dry_run)?;
        Ok(json!({ "status": "ok", "dry_run": dry_run, "message": msg }))
    }
}

pub struct HwTaskControlAction {
    backend: Arc<dyn HwBackend>,
}
impl ActionCommand for HwTaskControlAction {
    fn command_id(&self) -> &'static str {
        "hw_task_control"
    }
    fn description(&self) -> &'static str {
        "Enable, disable, or run a Windows Scheduled Task"
    }
    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::Mutating
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "task_path": { "type": "string" },
                "action": { "type": "string", "enum": ["enable", "disable", "run"] }
            },
            "required": ["task_path", "action"],
            "additionalProperties": false
        })
    }
    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let task_path = args
            .get("task_path")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing 'task_path'".to_string()))?;
        let action = args
            .get("action")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing 'action'".to_string()))?;
        let msg = self.backend.control_task(task_path, action, dry_run)?;
        Ok(json!({ "status": "ok", "dry_run": dry_run, "message": msg }))
    }
}

pub struct HwCodecControlAction {
    backend: Arc<dyn HwBackend>,
}
impl ActionCommand for HwCodecControlAction {
    fn command_id(&self) -> &'static str {
        "hw_codec_control"
    }
    fn description(&self) -> &'static str {
        "Enable or disable an installed multimedia codec"
    }
    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::Mutating
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "codec_id": { "type": "string" },
                "enable": { "type": "boolean" }
            },
            "required": ["codec_id", "enable"],
            "additionalProperties": false
        })
    }
    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let cid = args
            .get("codec_id")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing 'codec_id'".to_string()))?;
        let enable = args
            .get("enable")
            .and_then(Value::as_bool)
            .ok_or_else(|| McpToolError::InvalidParams("missing boolean 'enable'".to_string()))?;
        let msg = self.backend.control_codec(cid, enable, dry_run)?;
        Ok(json!({ "status": "ok", "dry_run": dry_run, "message": msg }))
    }
}

#[cfg(test)]
mod tests {
    use guap_mcp::{McpServerRegistry, PolicyMode};

    use super::*;
    use crate::mock::MockHwBackend;
    use crate::parsers::{decode_reg_tzi, parse_acpi_table, parse_smbios_raw_data, parse_task_scheduler_xml};

    #[test]
    fn all_10_hw_providers_work_offline() {
        let backend: Arc<dyn HwBackend> = Arc::new(MockHwBackend::new());
        let providers = all_hw_providers(backend, Sys2RustConfig::default());
        assert_eq!(providers.len(), 10);
        for p in &providers {
            let data = p.query(&TableQuery::default()).unwrap();
            assert!(!data.rows.is_empty(), "provider {} empty", p.tool_id());
        }
    }

    #[test]
    fn smbios_acpi_task_xml_and_tzi_decoders() {
        let smbios = parse_smbios_raw_data(&MockHwBackend::synthetic_smbios_bytes()).unwrap();
        assert!(smbios.decoded_summary.contains("American Megatrends"));
        assert!(smbios.decoded_summary.contains("Ryzen 9 9950X"));
        assert!(smbios.decoded_summary.contains("16384MiB @5600MT/s"));

        // Invalid SMBIOS truncated guard
        assert!(parse_smbios_raw_data(&[0, 1, 2]).is_err());

        for raw in MockHwBackend::synthetic_acpi_tables() {
            let parsed = parse_acpi_table(&raw).unwrap();
            assert!(parsed.checksum_valid, "table {} checksum invalid", parsed.table_id);
        }
        let mut corrupt = MockHwBackend::synthetic_acpi_tables().pop().unwrap();
        corrupt[40] ^= 0xFF;
        assert!(!parse_acpi_table(&corrupt).unwrap().checksum_valid);

        // UTF-16LE Task XML with BOM
        let xml_str = r#"<?xml version="1.0" encoding="UTF-16"?><Task version="1.4"><Triggers><LogonTrigger/></Triggers><Actions><Exec><Command>notepad.exe</Command></Exec></Actions></Task>"#;
        let mut utf16 = vec![0xFFu8, 0xFEu8];
        for u in xml_str.encode_utf16() {
            utf16.extend_from_slice(&u.to_le_bytes());
        }
        let task = parse_task_scheduler_xml(r"\Custom", "LogonNote", &utf16).unwrap();
        assert_eq!(task.actions, "notepad.exe");
        assert!(task.triggers.contains("LogonTrigger"));

        let tzi = decode_reg_tzi(&MockHwBackend::synthetic_eastern_tzi_bytes()).unwrap();
        assert_eq!(tzi.utc_offset_min, -300);
        assert!(tzi.supports_dst);
        assert_eq!(tzi.dst_start_rule, "Mar 2nd Sun 02:00");
        assert_eq!(tzi.dst_end_rule, "Nov 1st Sun 02:00");
    }

    #[test]
    fn battery_missing_hardware_returns_structured_diagnostic_and_policy_gates_work() {
        let no_bat: Arc<dyn HwBackend> = Arc::new(MockHwBackend::new().with_no_battery_hardware(true));
        let err = HwBatteryProvider::new(no_bat)
            .query(&TableQuery::default())
            .unwrap_err();
        assert!(err.to_string().contains("[HARDWARE_NOT_FOUND]"));

        let backend: Arc<dyn HwBackend> = Arc::new(MockHwBackend::new());
        let mut reg = McpServerRegistry::new(PolicyMode::ReadOnlyOnly);
        for a in all_hw_actions(Arc::clone(&backend)) {
            reg.register_action(a);
        }
        let denied = reg
            .dispatch(
                "hw_service_control",
                &json!({ "service_name": "Spooler", "action": "start", "confirm_destructive": true }),
            )
            .unwrap_err();
        assert_eq!(denied.code, -32003);

        reg.set_policy(PolicyMode::AllowMutating);
        let ok = reg
            .dispatch(
                "hw_service_control",
                &json!({ "service_name": "Spooler", "action": "start", "confirm_destructive": true }),
            )
            .unwrap();
        assert_eq!(ok["status"], json!("ok"));
        assert_eq!(
            backend
                .list_services()
                .unwrap()
                .into_iter()
                .find(|s| s.service_name == "Spooler")
                .unwrap()
                .status,
            "Running"
        );
    }

    #[test]
    fn regression_offset_overflow_driver_dedup_and_error_mapping() {
        use crate::parsers::{current_local_from_offset, filter_non_null_driver_addrs, normalize_driver_path};
        use chrono::{TimeZone, Utc};

        // 1. current_local_from_offset must never panic on extreme offsets
        let base = Utc.with_ymd_and_hms(2026, 11, 23, 12, 0, 0).unwrap();
        assert_eq!(current_local_from_offset(base, i64::MAX), base);
        assert_eq!(current_local_from_offset(base, i64::MIN), base);
        assert_eq!(
            current_local_from_offset(base, -300),
            Utc.with_ymd_and_hms(2026, 11, 23, 7, 0, 0).unwrap()
        );

        // 2. Unprivileged KASLR EnumDeviceDrivers all-NULL filtering & driver path normalization
        assert!(filter_non_null_driver_addrs(&[0, 0, 0]).is_empty());
        assert_eq!(
            filter_non_null_driver_addrs(&[
                0,
                0xFFFF_F800_0000_1000,
                0,
                0xFFFF_F800_0000_1000,
                0xFFFF_F800_0000_2000
            ]),
            vec![0xFFFF_F800_0000_1000, 0xFFFF_F800_0000_2000]
        );
        assert_eq!(
            normalize_driver_path(r"\SystemRoot\system32\drivers\ntfs.sys", r"C:\Windows"),
            r"C:\Windows\system32\drivers\ntfs.sys"
        );
        assert_eq!(
            normalize_driver_path(r"\??\C:\Windows\System32\drivers\pci.sys", r"C:\Windows"),
            r"C:\Windows\System32\drivers\pci.sys"
        );
        assert_eq!(
            normalize_driver_path(r"system32\drivers\disk.sys", r"C:\Windows"),
            r"C:\Windows\system32\drivers\disk.sys"
        );

        // 3. control_device error propagation maps E_ACCESSDENIED / ERROR_ACCESS_DENIED to PermissionDenied
        #[cfg(windows)]
        {
            use crate::live_win32::map_win32_error;
            let denied = map_win32_error(
                "SetupDiCallClassInstaller",
                windows::core::Error::from_hresult(windows::core::HRESULT(0x8007_0005u32 as i32)),
            );
            assert!(matches!(denied, sys2rust_core::Sys2RustError::PermissionDenied { .. }));

            let other = map_win32_error(
                "SetupDiCallClassInstaller",
                windows::core::Error::from_hresult(windows::core::HRESULT(0x8007_0057u32 as i32)),
            );
            assert!(matches!(other, sys2rust_core::Sys2RustError::OsError { .. }));
        }
    }
}
