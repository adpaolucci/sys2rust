use std::sync::Arc;

use guap_mcp::{ActionCommand, ActionRiskLevel, McpToolError};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, TableData, TableError, TableProvider, TableQuery, TableSchema, apply_query,
};
use serde_json::{Value, json};
use sys2rust_core::binary::AccessMaskDecoder;

use crate::backend::ProcBackend;

pub fn all_proc_providers(backend: Arc<dyn ProcBackend>) -> Vec<Arc<dyn TableProvider>> {
    vec![
        Arc::new(ProcThreadsProvider::new(Arc::clone(&backend))),
        Arc::new(ProcDllsProvider::new(Arc::clone(&backend))),
        Arc::new(ProcHandlesProvider::new(Arc::clone(&backend))),
        Arc::new(ProcOpenFilesProvider::new(Arc::clone(&backend))),
        Arc::new(ProcActivityProvider::new(Arc::clone(&backend))),
        Arc::new(ProcHeapProvider::new(Arc::clone(&backend))),
        Arc::new(ProcGdiProvider::new(Arc::clone(&backend))),
        Arc::new(ProcHangProvider::new(Arc::clone(&backend))),
        Arc::new(ProcDebugProvider::new(Arc::clone(&backend))),
        Arc::new(ProcListProvider::new(Arc::clone(&backend))),
        Arc::new(ProcMemProvider::new(Arc::clone(&backend))),
        Arc::new(ProcEnvProvider::new(Arc::clone(&backend))),
        Arc::new(ProcEtwLifeProvider::new(backend)),
    ]
}

pub fn all_proc_actions(backend: Arc<dyn ProcBackend>) -> Vec<Arc<dyn ActionCommand>> {
    vec![
        Arc::new(ProcTerminateAction {
            backend: Arc::clone(&backend),
        }),
        Arc::new(ProcThreadControlAction {
            backend: Arc::clone(&backend),
        }),
        Arc::new(ProcCloseHandleAction {
            backend: Arc::clone(&backend),
        }),
        Arc::new(ProcDebugAttachAction { backend }),
    ]
}

fn hex_u64(v: u64) -> CellValue {
    CellValue::Hex(v.to_be_bytes().to_vec())
}

// 1. proc_threads (ProcessThreadsView)
pub struct ProcThreadsProvider {
    backend: Arc<dyn ProcBackend>,
}
impl ProcThreadsProvider {
    pub fn new(backend: Arc<dyn ProcBackend>) -> Self {
        Self { backend }
    }
}
impl TableProvider for ProcThreadsProvider {
    fn tool_id(&self) -> &'static str {
        "proc_threads"
    }
    fn description(&self) -> &'static str {
        "Inspect running Windows threads, start addresses, priorities, states, and wait reasons (ProcessThreadsView)"
    }
    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Process Threads (ProcessThreadsView)",
            vec![
                ColumnDef::new("tid", "TID", ColumnType::Uint).with_width_hint(80),
                ColumnDef::new("pid", "PID", ColumnType::Uint).with_width_hint(80),
                ColumnDef::new("process_name", "Process", ColumnType::Text).with_width_hint(150),
                ColumnDef::new("start_address", "Start Address", ColumnType::Hex).with_width_hint(140),
                ColumnDef::new("context_switches", "Context Switches", ColumnType::Uint).with_width_hint(110),
                ColumnDef::new("priority", "Priority", ColumnType::Int).with_width_hint(80),
                ColumnDef::new("base_priority", "Base Priority", ColumnType::Int).with_width_hint(90),
                ColumnDef::new("state", "State", ColumnType::Text).with_width_hint(100),
                ColumnDef::new("wait_reason", "Wait Reason", ColumnType::Text).with_width_hint(130),
                ColumnDef::new("user_time", "User Time (ms)", ColumnType::Duration).with_width_hint(110),
                ColumnDef::new("kernel_time", "Kernel Time (ms)", ColumnType::Duration).with_width_hint(110),
                ColumnDef::new("created_time", "Created Time", ColumnType::Timestamp).with_width_hint(170),
            ],
        )
    }
    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let items = self.backend.list_threads(None)?;
        let rows: Vec<Row> = items
            .into_iter()
            .enumerate()
            .map(|(i, t)| {
                Row::new(
                    (i + 1) as u64,
                    vec![
                        CellValue::Uint(u64::from(t.tid)),
                        CellValue::Uint(u64::from(t.pid)),
                        CellValue::Text(t.process_name.clone()),
                        hex_u64(t.start_address),
                        CellValue::Uint(t.context_switches),
                        CellValue::Int(i64::from(t.priority)),
                        CellValue::Int(i64::from(t.base_priority)),
                        CellValue::Text(t.state.clone()),
                        CellValue::Text(t.wait_reason.clone()),
                        CellValue::Uint(t.user_time_ms),
                        CellValue::Uint(t.kernel_time_ms),
                        t.created_time.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                    ],
                )
                .with_detail_json(json!(t))
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}

// 2. proc_dlls (LoadedDllsView)
pub struct ProcDllsProvider {
    backend: Arc<dyn ProcBackend>,
}
impl ProcDllsProvider {
    pub fn new(backend: Arc<dyn ProcBackend>) -> Self {
        Self { backend }
    }
}
impl TableProvider for ProcDllsProvider {
    fn tool_id(&self) -> &'static str {
        "proc_dlls"
    }
    fn description(&self) -> &'static str {
        "Inspect loaded DLL modules across processes with version metadata (LoadedDllsView)"
    }
    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Loaded DLLs (LoadedDllsView)",
            vec![
                ColumnDef::new("dll_path", "DLL Path", ColumnType::Text).with_width_hint(240),
                ColumnDef::new("dll_name", "DLL Name", ColumnType::Text).with_width_hint(140),
                ColumnDef::new("process_count", "Processes", ColumnType::Uint).with_width_hint(85),
                ColumnDef::new("processes", "Process List", ColumnType::Text).with_width_hint(200),
                ColumnDef::new("base_address", "Base Address", ColumnType::Hex).with_width_hint(135),
                ColumnDef::new("size", "Size", ColumnType::BytesSize).with_width_hint(100),
                ColumnDef::new("product_name", "Product Name", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("file_version", "Version", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("company", "Company", ColumnType::Text).with_width_hint(150),
                ColumnDef::new("signed", "Signed", ColumnType::Bool).with_width_hint(70),
            ],
        )
    }
    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let items = self.backend.list_loaded_dlls(None)?;
        let rows: Vec<Row> = items
            .into_iter()
            .enumerate()
            .map(|(i, d)| {
                Row::new(
                    (i + 1) as u64,
                    vec![
                        CellValue::Text(d.dll_path.clone()),
                        CellValue::Text(d.dll_name.clone()),
                        CellValue::Uint(u64::from(d.process_count)),
                        CellValue::Text(d.processes.clone()),
                        hex_u64(d.base_address),
                        CellValue::Bytes(d.size_bytes),
                        CellValue::Text(d.product_name.clone()),
                        CellValue::Text(d.file_version.clone()),
                        CellValue::Text(d.company.clone()),
                        CellValue::Bool(d.signed),
                    ],
                )
                .with_detail_json(json!(d))
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}

// 3. proc_handles (HandleView)
pub struct ProcHandlesProvider {
    backend: Arc<dyn ProcBackend>,
}
impl ProcHandlesProvider {
    pub fn new(backend: Arc<dyn ProcBackend>) -> Self {
        Self { backend }
    }
}
impl TableProvider for ProcHandlesProvider {
    fn tool_id(&self) -> &'static str {
        "proc_handles"
    }
    fn description(&self) -> &'static str {
        "Inspect open kernel handles per process with synchronous pipe deadlock guard (HandleView)"
    }
    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Process Handles (HandleView)",
            vec![
                ColumnDef::new("pid", "PID", ColumnType::Uint).with_width_hint(80),
                ColumnDef::new("process_name", "Process", ColumnType::Text).with_width_hint(140),
                ColumnDef::new("handle_value", "Handle", ColumnType::Hex).with_width_hint(100),
                ColumnDef::new("object_type", "Type", ColumnType::Text).with_width_hint(100),
                ColumnDef::new("object_name", "Object Name", ColumnType::Text).with_width_hint(260),
                ColumnDef::new("access_mask", "Access Mask", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("handle_count", "Handle Count", ColumnType::Uint).with_width_hint(90),
            ],
        )
    }
    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let items = self.backend.list_handles(None)?;
        let rows: Vec<Row> = items
            .into_iter()
            .enumerate()
            .map(|(i, h)| {
                Row::new(
                    (i + 1) as u64,
                    vec![
                        CellValue::Uint(u64::from(h.pid)),
                        CellValue::Text(h.process_name.clone()),
                        hex_u64(h.handle_value),
                        CellValue::Text(h.object_type.clone()),
                        CellValue::Text(h.object_name.clone()),
                        CellValue::Text(AccessMaskDecoder::decode_file_access(h.access_mask)),
                        CellValue::Uint(u64::from(h.handle_count)),
                    ],
                )
                .with_detail_json(json!(h))
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}

// 4. proc_open_files (OpenFilesView)
pub struct ProcOpenFilesProvider {
    backend: Arc<dyn ProcBackend>,
}
impl ProcOpenFilesProvider {
    pub fn new(backend: Arc<dyn ProcBackend>) -> Self {
        Self { backend }
    }
}
impl TableProvider for ProcOpenFilesProvider {
    fn tool_id(&self) -> &'static str {
        "proc_open_files"
    }
    fn description(&self) -> &'static str {
        "Inspect open file handles across processes with FILE_TYPE_PIPE timeout guard (OpenFilesView)"
    }
    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Open Files (OpenFilesView)",
            vec![
                ColumnDef::new("filename", "Filename", ColumnType::Text).with_width_hint(150),
                ColumnDef::new("full_path", "Full Path", ColumnType::Text).with_width_hint(250),
                ColumnDef::new("handle", "Handle", ColumnType::Hex).with_width_hint(90),
                ColumnDef::new("pid", "PID", ColumnType::Uint).with_width_hint(80),
                ColumnDef::new("process_name", "Process", ColumnType::Text).with_width_hint(140),
                ColumnDef::new("user_name", "User", ColumnType::Text).with_width_hint(140),
                ColumnDef::new("access_mask", "Access", ColumnType::Text).with_width_hint(170),
                ColumnDef::new("sharing_mode", "Sharing", ColumnType::Text).with_width_hint(100),
                ColumnDef::new("file_offset", "Offset", ColumnType::Uint).with_width_hint(90),
                ColumnDef::new("process_path", "Process Path", ColumnType::Text).with_width_hint(220),
            ],
        )
    }
    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let items = self.backend.list_open_files(None)?;
        let rows: Vec<Row> = items
            .into_iter()
            .enumerate()
            .map(|(i, f)| {
                Row::new(
                    (i + 1) as u64,
                    vec![
                        CellValue::Text(f.filename.clone()),
                        CellValue::Text(f.full_path.clone()),
                        hex_u64(f.handle),
                        CellValue::Uint(u64::from(f.pid)),
                        CellValue::Text(f.process_name.clone()),
                        CellValue::Text(f.user_name.clone()),
                        CellValue::Text(AccessMaskDecoder::decode_file_access(f.access_mask)),
                        CellValue::Text(f.sharing_mode.clone()),
                        CellValue::Uint(f.file_offset),
                        CellValue::Text(f.process_path.clone()),
                    ],
                )
                .with_detail_json(json!(f))
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}

// 5. proc_activity (ProcessActivityView via ETW Kernel-File)
pub struct ProcActivityProvider {
    backend: Arc<dyn ProcBackend>,
}
impl ProcActivityProvider {
    pub fn new(backend: Arc<dyn ProcBackend>) -> Self {
        Self { backend }
    }
}
impl TableProvider for ProcActivityProvider {
    fn tool_id(&self) -> &'static str {
        "proc_activity"
    }
    fn description(&self) -> &'static str {
        "Aggregate per-file I/O activity via passive ETW Microsoft-Windows-Kernel-File (ProcessActivityView)"
    }
    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Process File Activity (ETW Kernel-File)",
            vec![
                ColumnDef::new("file_path", "File Path", ColumnType::Text).with_width_hint(250),
                ColumnDef::new("open_count", "Opens", ColumnType::Uint).with_width_hint(80),
                ColumnDef::new("close_count", "Closes", ColumnType::Uint).with_width_hint(80),
                ColumnDef::new("read_count", "Reads", ColumnType::Uint).with_width_hint(80),
                ColumnDef::new("write_count", "Writes", ColumnType::Uint).with_width_hint(80),
                ColumnDef::new("read_bytes", "Read Bytes", ColumnType::BytesSize).with_width_hint(110),
                ColumnDef::new("write_bytes", "Write Bytes", ColumnType::BytesSize).with_width_hint(110),
                ColumnDef::new("last_activity_time", "Last Activity", ColumnType::Timestamp).with_width_hint(170),
                ColumnDef::new("pid", "PID", ColumnType::Uint).with_width_hint(80),
            ],
        )
    }
    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let items = self.backend.collect_file_activity()?;
        let rows: Vec<Row> = items
            .into_iter()
            .enumerate()
            .map(|(i, a)| {
                Row::new(
                    (i + 1) as u64,
                    vec![
                        CellValue::Text(a.file_path.clone()),
                        CellValue::Uint(a.open_count),
                        CellValue::Uint(a.close_count),
                        CellValue::Uint(a.read_count),
                        CellValue::Uint(a.write_count),
                        CellValue::Bytes(a.read_bytes),
                        CellValue::Bytes(a.write_bytes),
                        CellValue::Timestamp(a.last_activity_time),
                        CellValue::Uint(u64::from(a.pid)),
                    ],
                )
                .with_detail_json(json!(a))
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}

// 6. proc_heap (HeapMemView)
pub struct ProcHeapProvider {
    backend: Arc<dyn ProcBackend>,
}
impl ProcHeapProvider {
    pub fn new(backend: Arc<dyn ProcBackend>) -> Self {
        Self { backend }
    }
}
impl TableProvider for ProcHeapProvider {
    fn tool_id(&self) -> &'static str {
        "proc_heap"
    }
    fn description(&self) -> &'static str {
        "Inspect process heap blocks and ASCII/hex previews via ToolHelp + ReadProcessMemory (HeapMemView)"
    }
    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Process Heap Blocks (HeapMemView)",
            vec![
                ColumnDef::new("heap_id", "Heap ID", ColumnType::Hex).with_width_hint(130),
                ColumnDef::new("block_address", "Block Address", ColumnType::Hex).with_width_hint(135),
                ColumnDef::new("size_bytes", "Size", ColumnType::BytesSize).with_width_hint(100),
                ColumnDef::new("flags", "Flags", ColumnType::Text).with_width_hint(100),
                ColumnDef::new("ascii_preview", "ASCII Preview", ColumnType::Text).with_width_hint(200),
                ColumnDef::new("hex_preview", "Hex Preview", ColumnType::Text).with_width_hint(240),
            ],
        )
    }
    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let items = self.backend.list_heap_blocks(None)?;
        let rows: Vec<Row> = items
            .into_iter()
            .enumerate()
            .map(|(i, b)| {
                Row::new(
                    (i + 1) as u64,
                    vec![
                        hex_u64(b.heap_id),
                        hex_u64(b.block_address),
                        CellValue::Bytes(b.size_bytes),
                        CellValue::Text(b.flags.clone()),
                        CellValue::Text(b.ascii_preview.clone()),
                        CellValue::Text(b.hex_preview.clone()),
                    ],
                )
                .with_detail_json(json!(b))
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}

// 7. proc_gdi (GDIView)
pub struct ProcGdiProvider {
    backend: Arc<dyn ProcBackend>,
}
impl ProcGdiProvider {
    pub fn new(backend: Arc<dyn ProcBackend>) -> Self {
        Self { backend }
    }
}
impl TableProvider for ProcGdiProvider {
    fn tool_id(&self) -> &'static str {
        "proc_gdi"
    }
    fn description(&self) -> &'static str {
        "Inspect per-process GDI and USER object handle counters (GDIView)"
    }
    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Process GDI / USER Counters (GDIView)",
            vec![
                ColumnDef::new("pid", "PID", ColumnType::Uint).with_width_hint(80),
                ColumnDef::new("process_name", "Process", ColumnType::Text).with_width_hint(150),
                ColumnDef::new("pen", "Pen", ColumnType::Uint).with_width_hint(65),
                ColumnDef::new("brush", "Brush", ColumnType::Uint).with_width_hint(65),
                ColumnDef::new("font", "Font", ColumnType::Uint).with_width_hint(65),
                ColumnDef::new("bitmap", "Bitmap", ColumnType::Uint).with_width_hint(70),
                ColumnDef::new("region", "Region", ColumnType::Uint).with_width_hint(70),
                ColumnDef::new("dc", "DC", ColumnType::Uint).with_width_hint(65),
                ColumnDef::new("metafile", "Metafile", ColumnType::Uint).with_width_hint(75),
                ColumnDef::new("other_gdi", "Other GDI", ColumnType::Uint).with_width_hint(85),
                ColumnDef::new("all_gdi", "All GDI", ColumnType::Uint).with_width_hint(80),
                ColumnDef::new("user_objects", "USER Objects", ColumnType::Uint).with_width_hint(100),
            ],
        )
    }
    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let items = self.backend.list_gdi_counts(None)?;
        let rows: Vec<Row> = items
            .into_iter()
            .enumerate()
            .map(|(i, g)| {
                Row::new(
                    (i + 1) as u64,
                    vec![
                        CellValue::Uint(u64::from(g.pid)),
                        CellValue::Text(g.process_name.clone()),
                        CellValue::Uint(u64::from(g.pen)),
                        CellValue::Uint(u64::from(g.brush)),
                        CellValue::Uint(u64::from(g.font)),
                        CellValue::Uint(u64::from(g.bitmap)),
                        CellValue::Uint(u64::from(g.region)),
                        CellValue::Uint(u64::from(g.dc)),
                        CellValue::Uint(u64::from(g.metafile)),
                        CellValue::Uint(u64::from(g.other_gdi)),
                        CellValue::Uint(u64::from(g.all_gdi)),
                        CellValue::Uint(u64::from(g.user_objects)),
                    ],
                )
                .with_detail_json(json!(g))
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}

// 8. proc_hang (WhatIsHang)
pub struct ProcHangProvider {
    backend: Arc<dyn ProcBackend>,
}
impl ProcHangProvider {
    pub fn new(backend: Arc<dyn ProcBackend>) -> Self {
        Self { backend }
    }
}
impl TableProvider for ProcHangProvider {
    fn tool_id(&self) -> &'static str {
        "proc_hang"
    }
    fn description(&self) -> &'static str {
        "Diagnose hung windows using Wait Chain Traversal (WCT) and StackWalk64 (WhatIsHang)"
    }
    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Hung Window Diagnostics (WhatIsHang)",
            vec![
                ColumnDef::new("pid", "PID", ColumnType::Uint).with_width_hint(80),
                ColumnDef::new("process_name", "Process", ColumnType::Text).with_width_hint(140),
                ColumnDef::new("window_title", "Window Title", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("hang_duration", "Hang (ms)", ColumnType::Duration).with_width_hint(90),
                ColumnDef::new("blocked_thread_id", "Blocked TID", ColumnType::Uint).with_width_hint(95),
                ColumnDef::new("wait_reason", "Wait Reason", ColumnType::Text).with_width_hint(200),
                ColumnDef::new("call_stack", "Call Stack", ColumnType::Text).with_width_hint(260),
                ColumnDef::new("loaded_modules", "Modules", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("environment_strings", "Env", ColumnType::Text).with_width_hint(180),
            ],
        )
    }
    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let items = self.backend.detect_hung_windows()?;
        let rows: Vec<Row> = items
            .into_iter()
            .enumerate()
            .map(|(i, h)| {
                Row::new(
                    (i + 1) as u64,
                    vec![
                        CellValue::Uint(u64::from(h.pid)),
                        CellValue::Text(h.process_name.clone()),
                        CellValue::Text(h.window_title.clone()),
                        CellValue::Uint(h.hang_duration_ms),
                        CellValue::Uint(u64::from(h.blocked_thread_id)),
                        CellValue::Text(h.wait_reason.clone()),
                        CellValue::Text(h.call_stack.clone()),
                        CellValue::Text(h.loaded_modules.clone()),
                        CellValue::Text(h.environment_strings.clone()),
                    ],
                )
                .with_detail_json(json!(h))
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}

// 9. proc_debug (SimpleProgramDebugger)
pub struct ProcDebugProvider {
    backend: Arc<dyn ProcBackend>,
}
impl ProcDebugProvider {
    pub fn new(backend: Arc<dyn ProcBackend>) -> Self {
        Self { backend }
    }
}
impl TableProvider for ProcDebugProvider {
    fn tool_id(&self) -> &'static str {
        "proc_debug"
    }
    fn description(&self) -> &'static str {
        "Capture passive debug/module events without DLL injection (SimpleProgramDebugger)"
    }
    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Program Debug Events (SimpleProgramDebugger)",
            vec![
                ColumnDef::new("event_time", "Time", ColumnType::Timestamp).with_width_hint(170),
                ColumnDef::new("event_type", "Event Type", ColumnType::Text).with_width_hint(170),
                ColumnDef::new("pid", "PID", ColumnType::Uint).with_width_hint(80),
                ColumnDef::new("tid", "TID", ColumnType::Uint).with_width_hint(80),
                ColumnDef::new("address", "Address", ColumnType::Hex).with_width_hint(135),
                ColumnDef::new("detail", "Detail", ColumnType::Text).with_width_hint(260),
            ],
        )
    }
    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let items = self.backend.list_debug_events(None)?;
        let rows: Vec<Row> = items
            .into_iter()
            .enumerate()
            .map(|(i, e)| {
                Row::new(
                    (i + 1) as u64,
                    vec![
                        CellValue::Timestamp(e.event_time),
                        CellValue::Text(e.event_type.clone()),
                        CellValue::Uint(u64::from(e.pid)),
                        CellValue::Uint(u64::from(e.tid)),
                        hex_u64(e.address),
                        CellValue::Text(e.detail.clone()),
                    ],
                )
                .with_detail_json(json!(e))
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}

// 10. proc_list (Process Inventory)
pub struct ProcListProvider {
    backend: Arc<dyn ProcBackend>,
}
impl ProcListProvider {
    pub fn new(backend: Arc<dyn ProcBackend>) -> Self {
        Self { backend }
    }
}
impl TableProvider for ProcListProvider {
    fn tool_id(&self) -> &'static str {
        "proc_list"
    }
    fn description(&self) -> &'static str {
        "Enumerate running Windows processes, command lines, memory counters, CPU time, and integrity levels"
    }
    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Process Inventory",
            vec![
                ColumnDef::new("pid", "PID", ColumnType::Uint).with_width_hint(80),
                ColumnDef::new("parent_pid", "PPID", ColumnType::Uint).with_width_hint(80),
                ColumnDef::new("process_name", "Process Name", ColumnType::Text).with_width_hint(150),
                ColumnDef::new("command_line", "Command Line", ColumnType::Text).with_width_hint(250),
                ColumnDef::new("image_path", "Image Path", ColumnType::Text).with_width_hint(220),
                ColumnDef::new("session_id", "Session", ColumnType::Uint).with_width_hint(70),
                ColumnDef::new("user", "User", ColumnType::Text).with_width_hint(150),
                ColumnDef::new("working_set_bytes", "Working Set", ColumnType::BytesSize).with_width_hint(110),
                ColumnDef::new("private_bytes", "Private Bytes", ColumnType::BytesSize).with_width_hint(110),
                ColumnDef::new("cpu_time", "CPU (ms)", ColumnType::Duration).with_width_hint(90),
                ColumnDef::new("integrity_level", "Integrity", ColumnType::Text).with_width_hint(90),
            ],
        )
    }
    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let items = self.backend.list_processes()?;
        let rows: Vec<Row> = items
            .into_iter()
            .enumerate()
            .map(|(i, p)| {
                Row::new(
                    (i + 1) as u64,
                    vec![
                        CellValue::Uint(u64::from(p.pid)),
                        CellValue::Uint(u64::from(p.parent_pid)),
                        CellValue::Text(p.process_name.clone()),
                        CellValue::Text(p.command_line.clone()),
                        CellValue::Text(p.image_path.clone()),
                        CellValue::Uint(u64::from(p.session_id)),
                        CellValue::Text(p.user.clone()),
                        CellValue::Bytes(p.working_set_bytes),
                        CellValue::Bytes(p.private_bytes),
                        CellValue::Uint(p.cpu_time_ms),
                        CellValue::Text(p.integrity_level.clone()),
                    ],
                )
                .with_detail_json(json!(p))
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}

// 11. proc_mem (Process Memory Map)
pub struct ProcMemProvider {
    backend: Arc<dyn ProcBackend>,
}
impl ProcMemProvider {
    pub fn new(backend: Arc<dyn ProcBackend>) -> Self {
        Self { backend }
    }
}
impl TableProvider for ProcMemProvider {
    fn tool_id(&self) -> &'static str {
        "proc_mem"
    }
    fn description(&self) -> &'static str {
        "Inspect virtual address space regions via VirtualQueryEx and GetMappedFileNameW"
    }
    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Process Virtual Memory Map",
            vec![
                ColumnDef::new("pid", "PID", ColumnType::Uint).with_width_hint(80),
                ColumnDef::new("base_address", "Base Address", ColumnType::Hex).with_width_hint(135),
                ColumnDef::new("region_size", "Region Size", ColumnType::BytesSize).with_width_hint(110),
                ColumnDef::new("state", "State", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("protect", "Protection", ColumnType::Text).with_width_hint(140),
                ColumnDef::new("mem_type", "Type", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("mapped_file", "Mapped File", ColumnType::Text).with_width_hint(260),
            ],
        )
    }
    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let items = self.backend.list_memory_regions(None)?;
        let rows: Vec<Row> = items
            .into_iter()
            .enumerate()
            .map(|(i, m)| {
                Row::new(
                    (i + 1) as u64,
                    vec![
                        CellValue::Uint(u64::from(m.pid)),
                        hex_u64(m.base_address),
                        CellValue::Bytes(m.region_size),
                        CellValue::Text(m.state.clone()),
                        CellValue::Text(m.protect.clone()),
                        CellValue::Text(m.mem_type.clone()),
                        CellValue::Text(m.mapped_file.clone()),
                    ],
                )
                .with_detail_json(json!(m))
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}

// 12. proc_env (Process Environment)
pub struct ProcEnvProvider {
    backend: Arc<dyn ProcBackend>,
}
impl ProcEnvProvider {
    pub fn new(backend: Arc<dyn ProcBackend>) -> Self {
        Self { backend }
    }
}
impl TableProvider for ProcEnvProvider {
    fn tool_id(&self) -> &'static str {
        "proc_env"
    }
    fn description(&self) -> &'static str {
        "Inspect process PEB RTL_USER_PROCESS_PARAMETERS current directory and environment variables"
    }
    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "Process Environment (PEB)",
            vec![
                ColumnDef::new("pid", "PID", ColumnType::Uint).with_width_hint(80),
                ColumnDef::new("process_name", "Process", ColumnType::Text).with_width_hint(140),
                ColumnDef::new("current_dir", "Current Directory", ColumnType::Text).with_width_hint(200),
                ColumnDef::new("env_var_name", "Variable", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("env_var_value", "Value", ColumnType::Text).with_width_hint(280),
            ],
        )
    }
    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let items = self.backend.list_process_env(None)?;
        let rows: Vec<Row> = items
            .into_iter()
            .enumerate()
            .map(|(i, e)| {
                Row::new(
                    (i + 1) as u64,
                    vec![
                        CellValue::Uint(u64::from(e.pid)),
                        CellValue::Text(e.process_name.clone()),
                        CellValue::Text(e.current_dir.clone()),
                        CellValue::Text(e.env_var_name.clone()),
                        CellValue::Text(e.env_var_value.clone()),
                    ],
                )
                .with_detail_json(json!(e))
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}

// 13. proc_etw_life (ETW Process/Image Lifecycle)
pub struct ProcEtwLifeProvider {
    backend: Arc<dyn ProcBackend>,
}
impl ProcEtwLifeProvider {
    pub fn new(backend: Arc<dyn ProcBackend>) -> Self {
        Self { backend }
    }
}
impl TableProvider for ProcEtwLifeProvider {
    fn tool_id(&self) -> &'static str {
        "proc_etw_life"
    }
    fn description(&self) -> &'static str {
        "Monitor process start/stop and image loads via passive ETW Microsoft-Windows-Kernel-Process"
    }
    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "ETW Process & Image Lifecycle",
            vec![
                ColumnDef::new("timestamp", "Timestamp", ColumnType::Timestamp).with_width_hint(170),
                ColumnDef::new("event_type", "Event Type", ColumnType::Text).with_width_hint(120),
                ColumnDef::new("pid", "PID", ColumnType::Uint).with_width_hint(80),
                ColumnDef::new("parent_pid", "PPID", ColumnType::Uint).with_width_hint(80),
                ColumnDef::new("image_path", "Image Path", ColumnType::Text).with_width_hint(230),
                ColumnDef::new("exit_code", "Exit Code", ColumnType::Int).with_width_hint(90),
                ColumnDef::new("command_line", "Command Line", ColumnType::Text).with_width_hint(240),
            ],
        )
    }
    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let items = self.backend.collect_etw_lifecycle()?;
        let rows: Vec<Row> = items
            .into_iter()
            .enumerate()
            .map(|(i, ev)| {
                Row::new(
                    (i + 1) as u64,
                    vec![
                        CellValue::Timestamp(ev.timestamp),
                        CellValue::Text(ev.event_type.clone()),
                        CellValue::Uint(u64::from(ev.pid)),
                        CellValue::Uint(u64::from(ev.parent_pid)),
                        CellValue::Text(ev.image_path.clone()),
                        CellValue::Int(i64::from(ev.exit_code)),
                        CellValue::Text(ev.command_line.clone()),
                    ],
                )
                .with_detail_json(json!(ev))
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}

// --- Mutating ActionCommands ---

pub struct ProcTerminateAction {
    backend: Arc<dyn ProcBackend>,
}
impl ActionCommand for ProcTerminateAction {
    fn command_id(&self) -> &'static str {
        "proc_terminate"
    }
    fn description(&self) -> &'static str {
        "Terminate a running Windows process by PID (requires AllowMutating + confirm_destructive=true)"
    }
    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::Mutating
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "pid": { "type": "integer", "minimum": 1 },
                "exit_code": { "type": "integer", "default": 1 }
            },
            "required": ["pid"],
            "additionalProperties": false
        })
    }
    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let pid = args
            .get("pid")
            .and_then(Value::as_u64)
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| McpToolError::InvalidParams("missing valid integer 'pid'".to_string()))?;
        let exit_code = args.get("exit_code").and_then(Value::as_u64).unwrap_or(1) as u32;
        let msg = self.backend.terminate_process(pid, exit_code, dry_run)?;
        Ok(json!({ "status": "ok", "dry_run": dry_run, "message": msg }))
    }
}

pub struct ProcThreadControlAction {
    backend: Arc<dyn ProcBackend>,
}
impl ActionCommand for ProcThreadControlAction {
    fn command_id(&self) -> &'static str {
        "proc_thread_control"
    }
    fn description(&self) -> &'static str {
        "Suspend or resume a thread by TID via standard Win32 SuspendThread/ResumeThread"
    }
    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::Mutating
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "tid": { "type": "integer", "minimum": 1 },
                "action": { "type": "string", "enum": ["suspend", "resume"] }
            },
            "required": ["tid", "action"],
            "additionalProperties": false
        })
    }
    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let tid = args
            .get("tid")
            .and_then(Value::as_u64)
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| McpToolError::InvalidParams("missing valid integer 'tid'".to_string()))?;
        let action = args
            .get("action")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing 'action' (suspend|resume)".to_string()))?;
        let suspend = match action {
            "suspend" => true,
            "resume" => false,
            other => return Err(McpToolError::InvalidParams(format!("unknown action '{other}'"))),
        };
        let msg = self.backend.control_thread(tid, suspend, dry_run)?;
        Ok(json!({ "status": "ok", "dry_run": dry_run, "message": msg }))
    }
}

pub struct ProcCloseHandleAction {
    backend: Arc<dyn ProcBackend>,
}
impl ActionCommand for ProcCloseHandleAction {
    fn command_id(&self) -> &'static str {
        "proc_close_handle"
    }
    fn description(&self) -> &'static str {
        "Close a handle in a target process via DuplicateHandle(DUPLICATE_CLOSE_SOURCE)"
    }
    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::PrivilegedMutating
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "pid": { "type": "integer", "minimum": 1 },
                "handle": { "type": "integer", "minimum": 1 }
            },
            "required": ["pid", "handle"],
            "additionalProperties": false
        })
    }
    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let pid = args
            .get("pid")
            .and_then(Value::as_u64)
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| McpToolError::InvalidParams("missing valid integer 'pid'".to_string()))?;
        let handle = args
            .get("handle")
            .and_then(Value::as_u64)
            .ok_or_else(|| McpToolError::InvalidParams("missing valid integer 'handle'".to_string()))?;
        let msg = self.backend.close_remote_handle(pid, handle, dry_run)?;
        Ok(json!({ "status": "ok", "dry_run": dry_run, "message": msg }))
    }
}

pub struct ProcDebugAttachAction {
    backend: Arc<dyn ProcBackend>,
}
impl ActionCommand for ProcDebugAttachAction {
    fn command_id(&self) -> &'static str {
        "proc_debug_attach"
    }
    fn description(&self) -> &'static str {
        "Attach standard Win32 DebugActiveProcess probe briefly and detach cleanly"
    }
    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::Mutating
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "pid": { "type": "integer", "minimum": 1 },
                "timeout_ms": { "type": "integer", "default": 200 }
            },
            "required": ["pid"],
            "additionalProperties": false
        })
    }
    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let pid = args
            .get("pid")
            .and_then(Value::as_u64)
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| McpToolError::InvalidParams("missing valid integer 'pid'".to_string()))?;
        let timeout_ms = args.get("timeout_ms").and_then(Value::as_u64).unwrap_or(200);
        let evs = self.backend.attach_debugger_probe(pid, timeout_ms, dry_run)?;
        Ok(json!({ "status": "ok", "dry_run": dry_run, "events": evs }))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;
    use std::time::Instant;

    use guap_mcp::{McpServerRegistry, PolicyMode};

    use super::*;
    use crate::backend::{parse_peb_environment_block, query_with_timeout};
    use crate::mock::MockProcBackend;

    #[test]
    fn all_13_proc_providers_work_offline_on_mock_backend() {
        let backend: Arc<dyn ProcBackend> = Arc::new(MockProcBackend::new());
        let providers = all_proc_providers(Arc::clone(&backend));
        assert_eq!(providers.len(), 13);

        for p in &providers {
            let data = p.query(&TableQuery::default()).unwrap();
            assert!(
                !data.rows.is_empty(),
                "provider {} returned empty rows on mock backend",
                p.tool_id()
            );
        }
    }

    #[test]
    fn etw_kernel_file_and_process_decoders_and_peb_env() {
        let file_events = crate::backend::decode_kernel_file_events(&MockProcBackend::synthetic_kernel_file_events());
        assert_eq!(file_events.len(), 1);
        assert_eq!(file_events[0].file_path, r"C:\work\data.bin");
        assert_eq!(file_events[0].open_count, 1);
        assert_eq!(file_events[0].read_count, 1);
        assert_eq!(file_events[0].read_bytes, 4096);
        assert_eq!(file_events[0].write_count, 1);
        assert_eq!(file_events[0].write_bytes, 1024);
        assert_eq!(file_events[0].close_count, 1);

        let proc_events =
            crate::backend::decode_kernel_process_events(&MockProcBackend::synthetic_kernel_process_events());
        assert_eq!(proc_events.len(), 3);
        assert_eq!(proc_events[0].event_type, "ProcessStart");
        assert_eq!(proc_events[0].command_line, "cmd.exe /c whoami");
        assert_eq!(proc_events[1].event_type, "ImageLoad");
        assert_eq!(proc_events[2].event_type, "ProcessStop");

        let mut env_raw: Vec<u8> = "=C:=C:\\work\0PATH=C:\\Windows\0TEMP=C:\\Temp\0\0"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        env_raw.push(0xAA); // trailing odd byte edge case
        let parsed = parse_peb_environment_block(&env_raw);
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0], ("=C:".to_string(), r"C:\work".to_string()));
        assert_eq!(parsed[1], ("PATH".to_string(), r"C:\Windows".to_string()));
    }

    #[test]
    fn pipe_timeout_guard_prevents_blocking_indefinitely() {
        let stalled = AtomicUsize::new(0);
        let t0 = Instant::now();
        let res = query_with_timeout(25, &stalled, || {
            std::thread::sleep(std::time::Duration::from_millis(300));
            Some("never".to_string())
        });
        assert!(t0.elapsed().as_millis() < 200);
        assert!(res.contains("timeout"));
    }

    #[test]
    fn non_privileged_etw_error_reports_permission_denied_gracefully() {
        let backend: Arc<dyn ProcBackend> = Arc::new(MockProcBackend::new().with_deny_privileged(true));
        let act = ProcActivityProvider::new(Arc::clone(&backend));
        let err = act.query(&TableQuery::default()).unwrap_err();
        assert!(err.to_string().contains("[PERMISSION_DENIED]"));
    }

    #[test]
    fn proc_action_commands_enforce_policy_gates_and_mutate_mock() {
        let backend: Arc<dyn ProcBackend> = Arc::new(MockProcBackend::new());
        let mut reg = McpServerRegistry::new(PolicyMode::ReadOnlyOnly);
        for p in all_proc_providers(Arc::clone(&backend)) {
            reg.register_table(p);
        }
        for a in all_proc_actions(Arc::clone(&backend)) {
            reg.register_action(a);
        }

        // Denied under ReadOnlyOnly
        let denied = reg
            .dispatch("proc_terminate", &json!({ "pid": 4200, "confirm_destructive": true }))
            .unwrap_err();
        assert_eq!(denied.code, -32003);

        // Denied under AllowMutating without confirm_destructive=true
        reg.set_policy(PolicyMode::AllowMutating);
        let unconfirmed = reg.dispatch("proc_terminate", &json!({ "pid": 4200 })).unwrap_err();
        assert_eq!(unconfirmed.code, -32003);

        // Dry run preserves process
        let dry = reg
            .dispatch(
                "proc_terminate",
                &json!({ "pid": 4200, "confirm_destructive": true, "dry_run": true }),
            )
            .unwrap();
        assert_eq!(dry["dry_run"], json!(true));
        assert_eq!(backend.list_processes().unwrap().len(), 3);

        // Real execution removes process from mock state
        let ok = reg
            .dispatch(
                "proc_terminate",
                &json!({ "pid": 4200, "confirm_destructive": true, "dry_run": false }),
            )
            .unwrap();
        assert_eq!(ok["status"], json!("ok"));
        assert_eq!(backend.list_processes().unwrap().len(), 2);
    }
}
