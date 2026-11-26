#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;

use guap_export::{
    CustodyLeaf, CustodyManifest, ExportError, ExportFormat, ExportOptions, build_custody_manifest, export_table,
    sha256_hex, sha512_hex, write_custody_manifest_json, write_table_export,
};
use guap_table::TableData;

pub fn default_export_options(title_override: Option<String>) -> ExportOptions {
    ExportOptions {
        title_override,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        ..ExportOptions::default()
    }
}

pub fn render_table_report(
    data: &TableData,
    format: ExportFormat,
    opts: &ExportOptions,
) -> Result<Vec<u8>, ExportError> {
    export_table(data, format, opts)
}

pub fn write_table_report(
    data: &TableData,
    path: &Path,
    format: ExportFormat,
    opts: &ExportOptions,
) -> Result<CustodyManifest, ExportError> {
    write_table_export(data, path, format, opts)
}

pub fn write_bundle_report(
    tables: &[TableData],
    out_dir: &Path,
    format: ExportFormat,
    opts: &ExportOptions,
) -> Result<CustodyManifest, ExportError> {
    fs::create_dir_all(out_dir)?;
    let mut leaves = Vec::with_capacity(tables.len());

    for (idx, table) in tables.iter().enumerate() {
        let safe_id: String = table
            .schema
            .tool_id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let file_path = out_dir.join(format!("{safe_id}.{}", format.extension()));
        let bytes = export_table(table, format, opts)?;
        fs::write(&file_path, &bytes)?;
        leaves.push(CustodyLeaf {
            index: idx,
            path: file_path.display().to_string(),
            size_bytes: bytes.len() as u64,
            sha256: sha256_hex(&bytes),
            sha512: sha512_hex(&bytes),
        });
    }

    let manifest = build_custody_manifest("sys2rust_bundle", &opts.tool_version, leaves);
    let manifest_path = out_dir.join("custody_manifest.json");
    write_custody_manifest_json(&manifest, &manifest_path)?;
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use guap_table::{CellValue, ColumnDef, ColumnType, Row, TableSchema};

    use super::*;

    fn sample_table(tool_id: &str) -> TableData {
        let schema = TableSchema::new(
            tool_id,
            "Sample Report",
            vec![
                ColumnDef::new("name", "Name", ColumnType::Text),
                ColumnDef::new("value", "Value", ColumnType::Text),
            ],
        );
        TableData {
            schema,
            rows: vec![
                Row::new(1, vec![CellValue::Text("cmd".into()), CellValue::Text("=1+1".into())]),
                Row::new(2, vec![CellValue::Text("ok".into()), CellValue::Text("normal".into())]),
            ],
            total_rows: 2,
        }
    }

    #[test]
    fn all_seven_export_formats_and_merkle_bundle_succeed() {
        let data = sample_table("proc_list");
        let opts = default_export_options(None);
        let formats = [
            ExportFormat::Csv,
            ExportFormat::Tsv,
            ExportFormat::Json,
            ExportFormat::Jsonl,
            ExportFormat::Html,
            ExportFormat::HtmlVertical,
            ExportFormat::Markdown,
        ];

        for fmt in formats {
            let bytes = render_table_report(&data, fmt, &opts).unwrap();
            assert!(!bytes.is_empty(), "empty export for {fmt:?}");
            if fmt == ExportFormat::Csv {
                let s = String::from_utf8(bytes).unwrap();
                assert!(s.contains("'=1+1"), "formula neutralization missing in CSV: {s}");
            }
        }

        let tmp = tempfile::tempdir().unwrap();
        let single_path = tmp.path().join("single.json");
        let single_manifest = write_table_report(&data, &single_path, ExportFormat::Json, &opts).unwrap();
        assert_eq!(single_manifest.artifact_count, 1);
        assert_eq!(single_manifest.merkle_root_sha256.len(), 64);
        assert_eq!(single_manifest.merkle_root_sha512.len(), 128);

        let bundle_dir = tmp.path().join("bundle");
        let tables = vec![sample_table("proc_list"), sample_table("pe_info")];
        let bundle = write_bundle_report(&tables, &bundle_dir, ExportFormat::Markdown, &opts).unwrap();
        assert_eq!(bundle.artifact_count, 2);
        assert!(bundle_dir.join("proc_list.md").is_file());
        assert!(bundle_dir.join("pe_info.md").is_file());
        assert!(bundle_dir.join("custody_manifest.json").is_file());
    }
}
