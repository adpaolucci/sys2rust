use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use serde_json::json;
use sys2rust_core::Sys2RustError;
use sys2rust_core::binary::dos_timestamp_to_datetime;

use crate::dotnet::parse_dotnet_metadata;
use crate::exports::parse_exports;
use crate::gac::{default_gac_roots, scan_gac_roots};
use crate::icons::reassemble_icons;
use crate::pe::PeFile;
use crate::resources::parse_resources;
use crate::version_cert::summarize_exe_info;

#[derive(Debug, Clone)]
pub enum PeTargetSource {
    FileOrDir {
        target: Option<PathBuf>,
        gac_root: Option<PathBuf>,
    },
    Bytes {
        label: String,
        bytes: Vec<u8>,
        gac_root: Option<PathBuf>,
    },
}

impl PeTargetSource {
    fn resolve_files(&self) -> Result<Vec<(String, Vec<u8>)>, TableError> {
        match self {
            Self::Bytes { label, bytes, .. } => Ok(vec![(label.clone(), bytes.clone())]),
            Self::FileOrDir { target, .. } => {
                let Some(path) = target else {
                    return Err(
                        Sys2RustError::InvalidArgument("no PE target file or directory specified".to_string()).into(),
                    );
                };
                if !path.exists() {
                    return Err(Sys2RustError::NotFound(path.display().to_string()).into());
                }
                if path.is_file() {
                    let bytes = fs::read(path).map_err(Sys2RustError::Io)?;
                    Ok(vec![(path.display().to_string(), bytes)])
                } else {
                    let mut out = Vec::new();
                    for dent in walkdir::WalkDir::new(path).max_depth(3).into_iter().flatten() {
                        if !dent.file_type().is_file() {
                            continue;
                        }
                        let p = dent.path();
                        let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
                        if matches!(
                            ext.to_ascii_lowercase().as_str(),
                            "exe" | "dll" | "sys" | "ocx" | "cpl" | "scr"
                        ) && let Ok(bytes) = fs::read(p)
                        {
                            out.push((p.display().to_string(), bytes));
                        }
                    }
                    Ok(out)
                }
            }
        }
    }

    fn gac_roots(&self) -> Vec<PathBuf> {
        let custom = match self {
            Self::FileOrDir { gac_root, .. } | Self::Bytes { gac_root, .. } => gac_root.clone(),
        };
        match custom {
            Some(r) => vec![r],
            None => default_gac_roots(),
        }
    }
}

pub struct PeExportsProvider {
    source: Arc<PeTargetSource>,
}

impl PeExportsProvider {
    pub fn new(source: Arc<PeTargetSource>) -> Self {
        Self { source }
    }
}

impl TableProvider for PeExportsProvider {
    fn tool_id(&self) -> &'static str {
        "pe_exports"
    }

    fn description(&self) -> &'static str {
        "Inspect named, ordinal-only, and forwarded DLL exports in pure Rust (DLLExportViewer equivalent)"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "PE Exports (DLLExportViewer)",
            vec![
                ColumnDef::new("function_name", "Function Name", ColumnType::Text).with_width_hint(220),
                ColumnDef::new("ordinal", "Ordinal", ColumnType::Uint).with_width_hint(80),
                ColumnDef::new("rva", "RVA", ColumnType::Hex).with_width_hint(110),
                ColumnDef::new("file_offset", "File Offset", ColumnType::Hex).with_width_hint(110),
                ColumnDef::new("forwarded_to", "Forwarded To", ColumnType::Text).with_width_hint(200),
                ColumnDef::new("dll_name", "DLL Name", ColumnType::Text).with_width_hint(150),
                ColumnDef::new("arch", "Architecture", ColumnType::Text).with_width_hint(110),
            ],
        )
        .with_default_sort(1, SortDirection::Asc)
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let files = self.source.resolve_files()?;
        let mut rows = Vec::new();
        let mut row_id = 1u64;

        for (label, bytes) in files {
            let pe = PeFile::parse(&bytes).map_err(TableError::from)?;
            let exports = parse_exports(&pe).map_err(TableError::from)?;
            for exp in exports {
                let rva_bytes = exp.rva.to_be_bytes().to_vec();
                let off_cell = exp
                    .file_offset
                    .map(|o| CellValue::Hex((o as u32).to_be_bytes().to_vec()))
                    .unwrap_or(CellValue::Null);
                let fwd_cell = exp.forwarded_to.clone().map(CellValue::Text).unwrap_or(CellValue::Null);
                let row = Row::new(
                    row_id,
                    vec![
                        CellValue::Text(exp.function_name.clone()),
                        CellValue::Uint(u64::from(exp.ordinal)),
                        CellValue::Hex(rva_bytes),
                        off_cell,
                        fwd_cell,
                        CellValue::Text(exp.dll_name.clone()),
                        CellValue::Text(exp.arch.clone()),
                    ],
                )
                .with_detail_json(json!({ "source": label, "export": exp }));
                rows.push(row);
                row_id += 1;
            }
        }

        apply_query(&self.schema(), &rows, req)
    }
}

pub struct PeResourcesProvider {
    source: Arc<PeTargetSource>,
}

impl PeResourcesProvider {
    pub fn new(source: Arc<PeTargetSource>) -> Self {
        Self { source }
    }
}

impl TableProvider for PeResourcesProvider {
    fn tool_id(&self) -> &'static str {
        "pe_resources"
    }

    fn description(&self) -> &'static str {
        "Inspect embedded .rsrc Win32 resources with MIME detection and SHA-256 (ResourcesExtract equivalent)"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "PE Resources (ResourcesExtract)",
            vec![
                ColumnDef::new("resource_type", "Type", ColumnType::Text).with_width_hint(140),
                ColumnDef::new("resource_name_or_id", "Name / ID", ColumnType::Text).with_width_hint(130),
                ColumnDef::new("language_id", "Lang ID", ColumnType::Uint).with_width_hint(80),
                ColumnDef::new("rva", "RVA", ColumnType::Hex).with_width_hint(110),
                ColumnDef::new("size_bytes", "Size", ColumnType::BytesSize).with_width_hint(100),
                ColumnDef::new("detected_mime", "MIME", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("sha256", "SHA-256", ColumnType::Text).with_width_hint(220),
            ],
        )
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let files = self.source.resolve_files()?;
        let mut rows = Vec::new();
        let mut row_id = 1u64;

        for (label, bytes) in files {
            let pe = PeFile::parse(&bytes).map_err(TableError::from)?;
            let resources = parse_resources(&pe).map_err(TableError::from)?;
            for res in resources {
                let row = Row::new(
                    row_id,
                    vec![
                        CellValue::Text(res.resource_type.clone()),
                        CellValue::Text(res.resource_name_or_id.clone()),
                        CellValue::Uint(u64::from(res.language_id)),
                        CellValue::Hex(res.rva.to_be_bytes().to_vec()),
                        CellValue::Bytes(u64::from(res.size_bytes)),
                        CellValue::Text(res.detected_mime.clone()),
                        CellValue::Text(res.sha256.clone()),
                    ],
                )
                .with_detail_json(json!({ "source": label, "resource": res }))
                .with_raw_bytes(res.data);
                rows.push(row);
                row_id += 1;
            }
        }

        apply_query(&self.schema(), &rows, req)
    }
}

pub struct PeIconsProvider {
    source: Arc<PeTargetSource>,
}

impl PeIconsProvider {
    pub fn new(source: Arc<PeTargetSource>) -> Self {
        Self { source }
    }
}

impl TableProvider for PeIconsProvider {
    fn tool_id(&self) -> &'static str {
        "pe_icons"
    }

    fn description(&self) -> &'static str {
        "Inspect and reassemble RT_GROUP_ICON / RT_GROUP_CURSOR payloads (IconsExtract equivalent)"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "PE Icons & Cursors (IconsExtract)",
            vec![
                ColumnDef::new("source_file", "Source File", ColumnType::Text).with_width_hint(200),
                ColumnDef::new("group_id", "Group ID", ColumnType::Text).with_width_hint(100),
                ColumnDef::new("icon_count", "Images", ColumnType::Uint).with_width_hint(80),
                ColumnDef::new("dimensions", "Dimensions", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("bit_depth", "Bit Depth", ColumnType::Uint).with_width_hint(90),
                ColumnDef::new("format", "Format", ColumnType::Text).with_width_hint(120),
                ColumnDef::new("sha256", "ICO SHA-256", ColumnType::Text).with_width_hint(220),
            ],
        )
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let files = self.source.resolve_files()?;
        let mut rows = Vec::new();
        let mut row_id = 1u64;

        for (label, bytes) in files {
            let pe = PeFile::parse(&bytes).map_err(TableError::from)?;
            let resources = parse_resources(&pe).map_err(TableError::from)?;
            let groups = reassemble_icons(&label, &resources);
            for grp in groups {
                let row = Row::new(
                    row_id,
                    vec![
                        CellValue::Text(grp.source_file.clone()),
                        CellValue::Text(grp.group_id.clone()),
                        CellValue::Uint(u64::from(grp.icon_count)),
                        CellValue::Text(grp.dimensions.clone()),
                        CellValue::Uint(u64::from(grp.bit_depth)),
                        CellValue::Text(grp.format.clone()),
                        CellValue::Text(grp.sha256.clone()),
                    ],
                )
                .with_detail_json(json!(grp))
                .with_raw_bytes(grp.ico_bytes);
                rows.push(row);
                row_id += 1;
            }
        }

        apply_query(&self.schema(), &rows, req)
    }
}

pub struct PeDotNetProvider {
    source: Arc<PeTargetSource>,
}

impl PeDotNetProvider {
    pub fn new(source: Arc<PeTargetSource>) -> Self {
        Self { source }
    }
}

impl TableProvider for PeDotNetProvider {
    fn tool_id(&self) -> &'static str {
        "pe_dotnet"
    }

    fn description(&self) -> &'static str {
        "Inspect ECMA-335 .NET assembly metadata and ManifestResource streams (DotNetResourcesExtract equivalent)"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            ".NET Embedded Resources (DotNetResourcesExtract)",
            vec![
                ColumnDef::new("assembly_name", "Assembly", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("resource_name", "Resource Name", ColumnType::Text).with_width_hint(220),
                ColumnDef::new("offset", "Offset", ColumnType::Uint).with_width_hint(90),
                ColumnDef::new("size_bytes", "Size", ColumnType::BytesSize).with_width_hint(100),
                ColumnDef::new("visibility", "Visibility", ColumnType::Text).with_width_hint(90),
                ColumnDef::new("embedded_type", "Embedded Type", ColumnType::Text).with_width_hint(170),
                ColumnDef::new("sha256", "SHA-256", ColumnType::Text).with_width_hint(220),
            ],
        )
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let files = self.source.resolve_files()?;
        let mut rows = Vec::new();
        let mut row_id = 1u64;

        for (label, bytes) in files {
            let pe = PeFile::parse(&bytes).map_err(TableError::from)?;
            if let Some(meta) = parse_dotnet_metadata(&pe).map_err(TableError::from)? {
                for res in meta.resources {
                    let row = Row::new(
                        row_id,
                        vec![
                            CellValue::Text(res.assembly_name.clone()),
                            CellValue::Text(res.resource_name.clone()),
                            CellValue::Uint(u64::from(res.offset)),
                            CellValue::Bytes(u64::from(res.size_bytes)),
                            CellValue::Text(res.visibility.clone()),
                            CellValue::Text(res.embedded_type.clone()),
                            CellValue::Text(res.sha256.clone()),
                        ],
                    )
                    .with_detail_json(json!({
                        "source": label,
                        "runtime_version": meta.runtime_version,
                        "assembly_version": meta.version,
                        "resource": res,
                    }))
                    .with_raw_bytes(res.data);
                    rows.push(row);
                    row_id += 1;
                }
            }
        }

        apply_query(&self.schema(), &rows, req)
    }
}

pub struct PeInfoProvider {
    source: Arc<PeTargetSource>,
}

impl PeInfoProvider {
    pub fn new(source: Arc<PeTargetSource>) -> Self {
        Self { source }
    }
}

impl TableProvider for PeInfoProvider {
    fn tool_id(&self) -> &'static str {
        "pe_info"
    }

    fn description(&self) -> &'static str {
        "Inspect PE32/PE32+ headers, version strings, Authenticode signature presence, and compiler hints (ExeInfo equivalent)"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            "PE Executable Info (ExeInfo)",
            vec![
                ColumnDef::new("file_path", "File Path", ColumnType::Text).with_width_hint(220),
                ColumnDef::new("machine", "Machine", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("subsystem", "Subsystem", ColumnType::Text).with_width_hint(120),
                ColumnDef::new("is_dotnet", ".NET", ColumnType::Bool).with_width_hint(70),
                ColumnDef::new("compiler_linker_hint", "Compiler / Linker", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("entry_point_rva", "EntryPoint RVA", ColumnType::Hex).with_width_hint(110),
                ColumnDef::new("time_date_stamp", "TimeDateStamp", ColumnType::Timestamp).with_width_hint(170),
                ColumnDef::new("sections_count", "Sections", ColumnType::Uint).with_width_hint(80),
                ColumnDef::new("file_version", "File Version", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("product_name", "Product Name", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("signed", "Signed", ColumnType::Bool).with_width_hint(70),
                ColumnDef::new("sha256", "SHA-256", ColumnType::Text).with_width_hint(220),
            ],
        )
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let files = self.source.resolve_files()?;
        let mut rows = Vec::new();

        for (idx, (label, bytes)) in files.into_iter().enumerate() {
            let pe = PeFile::parse(&bytes).map_err(TableError::from)?;
            let resources = parse_resources(&pe).unwrap_or_default();
            let info = summarize_exe_info(&label, &pe, &resources);
            let ts = dos_timestamp_to_datetime(info.time_date_stamp)
                .map(CellValue::Timestamp)
                .unwrap_or(CellValue::Null);
            let row = Row::new(
                (idx + 1) as u64,
                vec![
                    CellValue::Text(info.file_path.clone()),
                    CellValue::Text(info.machine.clone()),
                    CellValue::Text(info.subsystem.clone()),
                    CellValue::Bool(info.is_dotnet),
                    CellValue::Text(info.compiler_linker_hint.clone()),
                    CellValue::Hex(info.entry_point_rva.to_be_bytes().to_vec()),
                    ts,
                    CellValue::Uint(u64::from(info.sections_count)),
                    CellValue::Text(info.file_version.clone()),
                    CellValue::Text(info.product_name.clone()),
                    CellValue::Bool(info.signed),
                    CellValue::Text(info.sha256.clone()),
                ],
            )
            .with_detail_json(json!(info));
            rows.push(row);
        }

        apply_query(&self.schema(), &rows, req)
    }
}

pub struct PeGacProvider {
    source: Arc<PeTargetSource>,
}

impl PeGacProvider {
    pub fn new(source: Arc<PeTargetSource>) -> Self {
        Self { source }
    }
}

impl TableProvider for PeGacProvider {
    fn tool_id(&self) -> &'static str {
        "pe_gac"
    }

    fn description(&self) -> &'static str {
        "Enumerate .NET Global Assembly Cache (GAC) assemblies and versions (GACView equivalent)"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            self.tool_id(),
            ".NET Global Assembly Cache (GACView)",
            vec![
                ColumnDef::new("assembly_name", "Assembly Name", ColumnType::Text).with_width_hint(200),
                ColumnDef::new("version", "Version", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("culture", "Culture", ColumnType::Text).with_width_hint(80),
                ColumnDef::new("public_key_token", "Public Key Token", ColumnType::Text).with_width_hint(140),
                ColumnDef::new("processor_arch", "Arch", ColumnType::Text).with_width_hint(80),
                ColumnDef::new("file_path", "File Path", ColumnType::Text).with_width_hint(260),
                ColumnDef::new("modified_time", "Modified", ColumnType::Timestamp).with_width_hint(170),
                ColumnDef::new("file_size", "Size", ColumnType::BytesSize).with_width_hint(100),
            ],
        )
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let roots = self.source.gac_roots();
        let entries = scan_gac_roots(&roots).map_err(TableError::from)?;
        let rows: Vec<Row> = entries
            .into_iter()
            .enumerate()
            .map(|(idx, e)| {
                let ts = e.modified_time.map(CellValue::Timestamp).unwrap_or(CellValue::Null);
                Row::new(
                    (idx + 1) as u64,
                    vec![
                        CellValue::Text(e.assembly_name.clone()),
                        CellValue::Text(e.version.clone()),
                        CellValue::Text(e.culture.clone()),
                        CellValue::Text(e.public_key_token.clone()),
                        CellValue::Text(e.processor_arch.clone()),
                        CellValue::Text(e.file_path.clone()),
                        ts,
                        CellValue::Bytes(e.file_size),
                    ],
                )
                .with_detail_json(json!(e))
            })
            .collect();

        apply_query(&self.schema(), &rows, req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dotnet::extract_dotnet_resources;
    use crate::fixture::{build_synthetic_pe32_dll, build_synthetic_pe64_dotnet, create_synthetic_gac_tree};
    use crate::icons::extract_icons;
    use crate::resources::extract_resources;

    #[test]
    fn pe32_exports_resources_icons_and_info_roundtrip() {
        let bytes = build_synthetic_pe32_dll();
        let src = Arc::new(PeTargetSource::Bytes {
            label: "synth_pe32.dll".to_string(),
            bytes: bytes.clone(),
            gac_root: None,
        });

        let exports = PeExportsProvider::new(Arc::clone(&src))
            .query(&TableQuery::default())
            .unwrap();
        assert_eq!(exports.total_rows, 4);
        assert!(exports.rows.iter().any(|r| r.cells[0].to_string() == "FooInit"));
        assert!(exports.rows.iter().any(|r| r.cells[0].to_string() == "#Ordinal_5"));
        assert!(
            exports
                .rows
                .iter()
                .any(|r| r.cells[4].to_string() == "NTDLL.RtlAllocateHeap")
        );

        let resources = PeResourcesProvider::new(Arc::clone(&src))
            .query(&TableQuery::default())
            .unwrap();
        assert_eq!(resources.total_rows, 5);

        let icons = PeIconsProvider::new(Arc::clone(&src))
            .query(&TableQuery::default())
            .unwrap();
        assert_eq!(icons.total_rows, 1);
        assert_eq!(icons.rows[0].cells[2], CellValue::Uint(2));
        assert_eq!(icons.rows[0].cells[5], CellValue::Text("ICO (PNG+BMP)".to_string()));
        let ico_raw = icons.rows[0].raw_bytes.as_ref().unwrap();
        assert_eq!(&ico_raw[0..6], &[0, 0, 1, 0, 2, 0]);

        let info = PeInfoProvider::new(Arc::clone(&src))
            .query(&TableQuery::default())
            .unwrap();
        assert_eq!(info.total_rows, 1);
        assert_eq!(info.rows[0].cells[8], CellValue::Text("4.2.0.1".to_string()));
        assert_eq!(info.rows[0].cells[9], CellValue::Text("Sys2RustFixture".to_string()));
        assert_eq!(info.rows[0].cells[10], CellValue::Bool(true)); // WIN_CERTIFICATE

        let tmp = tempfile::tempdir().unwrap();
        let pe = PeFile::parse(&bytes).unwrap();
        let parsed_res = parse_resources(&pe).unwrap();
        let written_res = extract_resources(&parsed_res, &tmp.path().join("res")).unwrap();
        assert_eq!(written_res.len(), 5);
        let parsed_icons = reassemble_icons("synth_pe32.dll", &parsed_res);
        let written_icons = extract_icons(&parsed_icons, &tmp.path().join("ico")).unwrap();
        assert_eq!(written_icons.len(), 1);
    }

    #[test]
    fn pe64_dotnet_and_gac_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let dll_path = create_synthetic_gac_tree(tmp.path()).unwrap();

        let src = Arc::new(PeTargetSource::FileOrDir {
            target: Some(dll_path),
            gac_root: Some(tmp.path().to_path_buf()),
        });

        let dn = PeDotNetProvider::new(Arc::clone(&src))
            .query(&TableQuery::default())
            .unwrap();
        assert_eq!(dn.total_rows, 2);
        assert_eq!(dn.rows[0].cells[0], CellValue::Text("Sample.Lib".to_string()));
        assert_eq!(
            dn.rows[0].cells[1],
            CellValue::Text("Sample.Lib.g.resources".to_string())
        );
        assert_eq!(
            dn.rows[0].cells[5],
            CellValue::Text("ResourceManager (.resources)".to_string())
        );

        let pe_bytes = build_synthetic_pe64_dotnet();
        let pe = PeFile::parse(&pe_bytes).unwrap();
        let meta = parse_dotnet_metadata(&pe).unwrap().unwrap();
        let extracted = extract_dotnet_resources(&meta.resources, &tmp.path().join("dn")).unwrap();
        assert_eq!(extracted.len(), 2);

        let gac = PeGacProvider::new(src).query(&TableQuery::default()).unwrap();
        assert_eq!(gac.total_rows, 1);
        assert_eq!(gac.rows[0].cells[0], CellValue::Text("Sample.Lib".to_string()));
        assert_eq!(gac.rows[0].cells[1], CellValue::Text("1.2.3.4".to_string()));
        assert_eq!(gac.rows[0].cells[3], CellValue::Text("0123456789abcdef".to_string()));
    }

    #[test]
    fn malformed_and_truncated_pe_buffers_never_panic() {
        assert!(PeFile::parse(&[]).is_err());
        assert!(PeFile::parse(b"NOT_A_PE_FILE_AT_ALL_0123456789").is_err());

        let mut bad_lfanew = vec![0u8; 128];
        bad_lfanew[0..2].copy_from_slice(&0x5A4Du16.to_le_bytes());
        bad_lfanew[0x3C..0x40].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
        assert!(PeFile::parse(&bad_lfanew).is_err());

        let valid = build_synthetic_pe32_dll();
        for cut in [64usize, 128, 256, 512, 1024, 2048] {
            let truncated = &valid[..cut.min(valid.len())];
            if let Ok(pe) = PeFile::parse(truncated) {
                let _ = parse_exports(&pe);
                let _ = parse_resources(&pe);
                let _ = parse_dotnet_metadata(&pe);
            }
        }
    }

    #[test]
    fn duplicate_resource_extraction_multilang_icons_and_truncated_dotnet() {
        use crate::resources::{ResourceEntry, ResourceId};

        let tmp = tempfile::tempdir().unwrap();
        let make_res = |type_id: ResourceId, name_id: ResourceId, lang: u32, data: &[u8]| ResourceEntry {
            type_id: type_id.clone(),
            resource_type: crate::resources::resource_type_name(&type_id),
            name_id: name_id.clone(),
            resource_name_or_id: name_id.display(),
            language_id: lang,
            rva: 0x3000,
            file_offset: Some(0xA00),
            size_bytes: data.len() as u32,
            detected_mime: crate::resources::detect_resource_mime(&type_id, data).to_string(),
            sha256: sys2rust_core::binary::sha256_hex(data),
            data: data.to_vec(),
        };

        // 1. Duplicate (type, id, lang) resources (e.g. GNU ld dual RT_MANIFEST #1 1033)
        let r1 = make_res(ResourceId::Numeric(24), ResourceId::Numeric(1), 1033, b"<a/>");
        let r2 = make_res(ResourceId::Numeric(24), ResourceId::Numeric(1), 1033, b"<b/>");
        let extracted = extract_resources(&[r1, r2], tmp.path()).unwrap();
        assert_eq!(extracted.len(), 2);
        assert_ne!(extracted[0], extracted[1]);
        assert_eq!(std::fs::read(&extracted[0]).unwrap(), b"<a/>");
        assert_eq!(std::fs::read(&extracted[1]).unwrap(), b"<b/>");

        // 2. Multi-language icon reassembly pairs matching (id, language_id)
        let mut grp_1033 = vec![0, 0, 1, 0, 1, 0];
        grp_1033.extend_from_slice(&[16, 16, 0, 0, 1, 0, 32, 0, 12, 0, 0, 0, 1, 0]);
        let grp_1036 = grp_1033.clone();
        let icon_1033 = b"\x89PNG\r\n\x1a\n1033".to_vec();
        let icon_1036 = b"\x89PNG\r\n\x1a\n1036".to_vec();
        let entries = vec![
            make_res(ResourceId::Numeric(3), ResourceId::Numeric(1), 1033, &icon_1033),
            make_res(ResourceId::Numeric(3), ResourceId::Numeric(1), 1036, &icon_1036),
            make_res(ResourceId::Numeric(14), ResourceId::Numeric(101), 1033, &grp_1033),
            make_res(ResourceId::Numeric(14), ResourceId::Numeric(101), 1036, &grp_1036),
        ];
        let groups = reassemble_icons("multi.dll", &entries);
        assert_eq!(groups.len(), 2);
        assert!(groups[0].ico_bytes.ends_with(b"1033"));
        assert!(groups[1].ico_bytes.ends_with(b"1036"));

        // 3. Truncated .NET ManifestResource reports size_bytes = 0 and Truncated/Unavailable
        let mut pe_bytes = build_synthetic_pe64_dotnet();
        // Corrupt the length prefix of the first embedded resource at file offset 0x600 to 0x00FF_FFFF
        pe_bytes[0x600..0x604].copy_from_slice(&0x00FF_FFFFu32.to_le_bytes());
        let pe = PeFile::parse(&pe_bytes).unwrap();
        let meta = parse_dotnet_metadata(&pe).unwrap().unwrap();
        assert_eq!(meta.resources[0].size_bytes, 0);
        assert_eq!(meta.resources[0].embedded_type, "Truncated/Unavailable");
        assert!(meta.resources[0].data.is_empty());
    }
}
