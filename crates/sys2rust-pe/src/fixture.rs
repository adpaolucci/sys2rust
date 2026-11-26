use std::fs;
use std::path::{Path, PathBuf};

use sys2rust_core::Sys2RustResult;

fn push_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn push_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn push_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn pad_to(buf: &mut Vec<u8>, align: usize) {
    while !buf.len().is_multiple_of(align) {
        buf.push(0);
    }
}

type SectionSpec<'a> = (&'a [u8; 8], u32, u32, u32, u32, u32);

fn write_u32_at(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn build_version_info_blob() -> Vec<u8> {
    fn encode_utf16_z(s: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity((s.len() + 1) * 2);
        for u in s.encode_utf16() {
            out.extend_from_slice(&u.to_le_bytes());
        }
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    fn build_string_pair(key: &str, val: &str) -> Vec<u8> {
        let mut b = Vec::new();
        push_u16(&mut b, 0); // wLength placeholder
        let val_utf16 = encode_utf16_z(val);
        push_u16(&mut b, (val_utf16.len() / 2) as u16); // wValueLength in words
        push_u16(&mut b, 1); // wType = 1 (text)
        b.extend_from_slice(&encode_utf16_z(key));
        pad_to(&mut b, 4);
        b.extend_from_slice(&val_utf16);
        let len = b.len() as u16;
        b[0..2].copy_from_slice(&len.to_le_bytes());
        b
    }

    let mut lang_table = Vec::new();
    push_u16(&mut lang_table, 0);
    push_u16(&mut lang_table, 0);
    push_u16(&mut lang_table, 1);
    lang_table.extend_from_slice(&encode_utf16_z("040904B0"));
    pad_to(&mut lang_table, 4);
    for (k, v) in [
        ("FileVersion", "4.2.0.1"),
        ("ProductName", "Sys2RustFixture"),
        ("CompanyName", "GUAP Test Labs"),
        ("FileDescription", "Synthetic PE32 Fixture DLL"),
    ] {
        let child = build_string_pair(k, v);
        lang_table.extend_from_slice(&child);
        pad_to(&mut lang_table, 4);
    }
    let lt_len = lang_table.len() as u16;
    lang_table[0..2].copy_from_slice(&lt_len.to_le_bytes());

    let mut sfi = Vec::new();
    push_u16(&mut sfi, 0);
    push_u16(&mut sfi, 0);
    push_u16(&mut sfi, 1);
    sfi.extend_from_slice(&encode_utf16_z("StringFileInfo"));
    pad_to(&mut sfi, 4);
    sfi.extend_from_slice(&lang_table);
    let sfi_len = sfi.len() as u16;
    sfi[0..2].copy_from_slice(&sfi_len.to_le_bytes());

    let mut root = Vec::new();
    push_u16(&mut root, 0);
    push_u16(&mut root, 52); // VS_FIXEDFILEINFO size
    push_u16(&mut root, 0); // binary
    root.extend_from_slice(&encode_utf16_z("VS_VERSION_INFO"));
    pad_to(&mut root, 4);

    // VS_FIXEDFILEINFO (52 bytes)
    push_u32(&mut root, 0xFEEF_04BD);
    push_u32(&mut root, 0x0001_0000);
    push_u32(&mut root, 0x0004_0002); // 4.2
    push_u32(&mut root, 0x0000_0001); // 0.1
    push_u32(&mut root, 0x0004_0002);
    push_u32(&mut root, 0x0000_0001);
    push_u32(&mut root, 0x3F);
    push_u32(&mut root, 0);
    push_u32(&mut root, 0x0004_0004);
    push_u32(&mut root, 2); // VFT_DLL
    push_u32(&mut root, 0);
    push_u32(&mut root, 0);
    push_u32(&mut root, 0);
    pad_to(&mut root, 4);
    root.extend_from_slice(&sfi);

    let root_len = root.len() as u16;
    root[0..2].copy_from_slice(&root_len.to_le_bytes());
    root
}

/// Build a deterministic synthetic PE32 (`0x10B`) DLL with:
/// - Named (`FooInit`, `BarCalc`), ordinal-only (`#5`), and forwarded (`NTDLL.RtlAllocateHeap`) exports
/// - `.rsrc` 3-level tree (`RT_ICON` PNG + DIB, `RT_GROUP_ICON`, `RT_VERSION`, `RT_MANIFEST`)
/// - Raw-offset `WIN_CERTIFICATE` (`DataDir[4]`)
pub fn build_synthetic_pe32_dll() -> Vec<u8> {
    let mut img = vec![0u8; 0x1600];

    // DOS Header
    img[0..2].copy_from_slice(&0x5A4Du16.to_le_bytes());
    write_u32_at(&mut img, 0x3C, 0x80);

    // PE Signature + COFF (offset 0x80)
    write_u32_at(&mut img, 0x80, 0x0000_4550);
    img[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes()); // x86
    img[0x86..0x88].copy_from_slice(&3u16.to_le_bytes()); // 3 sections: .text, .rdata, .rsrc
    write_u32_at(&mut img, 0x88, 1_700_000_000);
    img[0x94..0x96].copy_from_slice(&224u16.to_le_bytes()); // SizeOfOptionalHeader (PE32)
    img[0x96..0x98].copy_from_slice(&0x2102u16.to_le_bytes()); // DLL

    // Optional Header PE32 (offset 0x98, size 224)
    let opt = 0x98usize;
    img[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
    img[opt + 2] = 14; // MajorLinkerVersion
    img[opt + 3] = 38;
    write_u32_at(&mut img, opt + 16, 0x1000); // EntryPoint
    write_u32_at(&mut img, opt + 28, 0x1000_0000); // ImageBase
    write_u32_at(&mut img, opt + 32, 0x1000);
    write_u32_at(&mut img, opt + 36, 0x200);
    img[opt + 68..opt + 70].copy_from_slice(&2u16.to_le_bytes()); // Windows GUI
    write_u32_at(&mut img, opt + 92, 16);

    // Section Table (offset 0x98 + 224 = 0x178)
    let sec_off = opt + 224;
    let sections: [SectionSpec<'_>; 3] = [
        (b".text\0\0\0", 0x200, 0x1000, 0x200, 0x400, 0x6000_0020),
        (b".rdata\0\0", 0x400, 0x2000, 0x400, 0x600, 0x4000_0040),
        (b".rsrc\0\0\0", 0xA00, 0x3000, 0xA00, 0xA00, 0x4000_0040),
    ];
    for (i, (name, vsz, va, rsz, rptr, ch)) in sections.iter().enumerate() {
        let s = sec_off + i * 40;
        img[s..s + 8].copy_from_slice(*name);
        write_u32_at(&mut img, s + 8, *vsz);
        write_u32_at(&mut img, s + 12, *va);
        write_u32_at(&mut img, s + 16, *rsz);
        write_u32_at(&mut img, s + 20, *rptr);
        write_u32_at(&mut img, s + 36, *ch);
    }

    // --- .rdata (file 0x600, RVA 0x2000): Export Directory ---
    // Export dir at RVA 0x2000 (file 0x600), size 0x200
    let exp_file = 0x600usize;
    let base_ord = 1u32;
    let num_funcs = 5u32; // ord 1..=5: 1=FooInit, 2=BarCalc, 3=Fwd, 4=0, 5=OrdOnly
    let num_names = 3u32;
    write_u32_at(&mut img, exp_file + 12, 0x2080); // Name RVA
    write_u32_at(&mut img, exp_file + 16, base_ord);
    write_u32_at(&mut img, exp_file + 20, num_funcs);
    write_u32_at(&mut img, exp_file + 24, num_names);
    write_u32_at(&mut img, exp_file + 28, 0x2030); // AddressOfFunctions
    write_u32_at(&mut img, exp_file + 32, 0x2050); // AddressOfNames
    write_u32_at(&mut img, exp_file + 36, 0x2060); // AddressOfNameOrdinals

    // AddressOfFunctions (file 0x630, RVA 0x2030)
    write_u32_at(&mut img, 0x630, 0x1010); // ord 1 FooInit
    write_u32_at(&mut img, 0x634, 0x1020); // ord 2 BarCalc
    write_u32_at(&mut img, 0x638, 0x20C0); // ord 3 Forwarded -> NTDLL.RtlAllocateHeap
    write_u32_at(&mut img, 0x63C, 0); // ord 4 unused
    write_u32_at(&mut img, 0x640, 0x1030); // ord 5 ordinal-only

    // AddressOfNames (file 0x650, RVA 0x2050)
    write_u32_at(&mut img, 0x650, 0x2090); // "BarCalc"
    write_u32_at(&mut img, 0x654, 0x20A0); // "FooInit"
    write_u32_at(&mut img, 0x658, 0x20B0); // "HeapAllocFwd"

    // AddressOfNameOrdinals (file 0x660, RVA 0x2060)
    img[0x660..0x662].copy_from_slice(&1u16.to_le_bytes()); // BarCalc -> func idx 1
    img[0x662..0x664].copy_from_slice(&0u16.to_le_bytes()); // FooInit -> func idx 0
    img[0x664..0x666].copy_from_slice(&2u16.to_le_bytes()); // HeapAllocFwd -> func idx 2

    img[0x680..0x68F].copy_from_slice(b"synth_pe32.dll\0");
    img[0x690..0x698].copy_from_slice(b"BarCalc\0");
    img[0x6A0..0x6A8].copy_from_slice(b"FooInit\0");
    img[0x6B0..0x6BD].copy_from_slice(b"HeapAllocFwd\0");
    img[0x6C0..0x6D6].copy_from_slice(b"NTDLL.RtlAllocateHeap\0");

    // DataDir[0] = Export
    write_u32_at(&mut img, opt + 96, 0x2000);
    write_u32_at(&mut img, opt + 100, 0x200);

    // --- .rsrc (file 0xA00, RVA 0x3000) ---
    let mut rsrc = Vec::new();
    // Root directory: 4 types (RT_ICON=3, RT_GROUP_ICON=14, RT_VERSION=16, RT_MANIFEST=24)
    let root_dir_sz = 16 + 4 * 8;
    rsrc.resize(root_dir_sz, 0);
    rsrc[14..16].copy_from_slice(&4u16.to_le_bytes()); // NumberOfIdEntries

    // Prepare payloads
    let mut png_icon = b"\x89PNG\r\n\x1a\n".to_vec();
    png_icon.extend_from_slice(&[0u8; 24]);

    let mut bmp_icon = Vec::new();
    push_u32(&mut bmp_icon, 40); // biSize
    push_u32(&mut bmp_icon, 32); // width
    push_u32(&mut bmp_icon, 64); // height * 2
    push_u16(&mut bmp_icon, 1);
    push_u16(&mut bmp_icon, 32);
    bmp_icon.resize(40 + 16, 0);

    let mut grp_icon = Vec::new();
    push_u16(&mut grp_icon, 0);
    push_u16(&mut grp_icon, 1); // ICO
    push_u16(&mut grp_icon, 2); // 2 images
    // Entry 1: 16x16 PNG (ID 1)
    grp_icon.extend_from_slice(&[16, 16, 0, 0]);
    push_u16(&mut grp_icon, 1);
    push_u16(&mut grp_icon, 32);
    push_u32(&mut grp_icon, png_icon.len() as u32);
    push_u16(&mut grp_icon, 1);
    // Entry 2: 32x32 BMP (ID 2)
    grp_icon.extend_from_slice(&[32, 32, 0, 0]);
    push_u16(&mut grp_icon, 1);
    push_u16(&mut grp_icon, 32);
    push_u32(&mut grp_icon, bmp_icon.len() as u32);
    push_u16(&mut grp_icon, 2);

    let ver_blob = build_version_info_blob();
    let manifest_blob = br#"<?xml version="1.0" encoding="UTF-8"?><assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"/>"#.to_vec();

    // Helper to build Level-2 (Name/ID) + Level-3 (Lang=1033) + DataEntry + payload
    struct TypeBucket {
        type_id: u32,
        items: Vec<(u32, Vec<u8>)>,
    }
    let buckets = [
        TypeBucket {
            type_id: 3,
            items: vec![(1, png_icon), (2, bmp_icon)],
        },
        TypeBucket {
            type_id: 14,
            items: vec![(101, grp_icon)],
        },
        TypeBucket {
            type_id: 16,
            items: vec![(1, ver_blob)],
        },
        TypeBucket {
            type_id: 24,
            items: vec![(1, manifest_blob)],
        },
    ];

    let mut payload_chunks: Vec<(usize, Vec<u8>)> = Vec::new();

    for (idx, bucket) in buckets.iter().enumerate() {
        let name_dir_off = rsrc.len();
        let root_entry_off = 16 + idx * 8;
        write_u32_at(&mut rsrc, root_entry_off, bucket.type_id);
        write_u32_at(&mut rsrc, root_entry_off + 4, 0x8000_0000 | (name_dir_off as u32));

        let nd_sz = 16 + bucket.items.len() * 8;
        rsrc.resize(name_dir_off + nd_sz, 0);
        rsrc[name_dir_off + 14..name_dir_off + 16].copy_from_slice(&(bucket.items.len() as u16).to_le_bytes());

        for (j, (item_id, data)) in bucket.items.iter().enumerate() {
            let lang_dir_off = rsrc.len();
            let ne_off = name_dir_off + 16 + j * 8;
            write_u32_at(&mut rsrc, ne_off, *item_id);
            write_u32_at(&mut rsrc, ne_off + 4, 0x8000_0000 | (lang_dir_off as u32));

            rsrc.resize(lang_dir_off + 24, 0); // 16B dir + 1 entry (8B)
            rsrc[lang_dir_off + 14..lang_dir_off + 16].copy_from_slice(&1u16.to_le_bytes());

            let data_entry_off = rsrc.len();
            write_u32_at(&mut rsrc, lang_dir_off + 16, 1033);
            write_u32_at(&mut rsrc, lang_dir_off + 20, data_entry_off as u32);

            rsrc.resize(data_entry_off + 16, 0);
            write_u32_at(&mut rsrc, data_entry_off + 4, data.len() as u32);
            payload_chunks.push((data_entry_off, data.clone()));
        }
    }

    pad_to(&mut rsrc, 4);
    for (data_entry_off, data) in payload_chunks {
        let data_rva = 0x3000 + rsrc.len() as u32;
        write_u32_at(&mut rsrc, data_entry_off, data_rva);
        rsrc.extend_from_slice(&data);
        pad_to(&mut rsrc, 4);
    }

    assert!(rsrc.len() <= 0xA00);
    img[0xA00..0xA00 + rsrc.len()].copy_from_slice(&rsrc);

    // DataDir[2] = Resource
    write_u32_at(&mut img, opt + 96 + 2 * 8, 0x3000);
    write_u32_at(&mut img, opt + 96 + 2 * 8 + 4, rsrc.len() as u32);

    // Append WIN_CERTIFICATE at raw offset 0x1400 (NOT RVA!)
    let cert_off = 0x1400usize;
    write_u32_at(&mut img, cert_off, 16); // dwLength
    img[cert_off + 4..cert_off + 6].copy_from_slice(&0x0200u16.to_le_bytes()); // WIN_CERT_REVISION_2_0
    img[cert_off + 6..cert_off + 8].copy_from_slice(&0x0002u16.to_le_bytes()); // PKCS_SIGNED_DATA
    write_u32_at(&mut img, opt + 96 + 4 * 8, cert_off as u32);
    write_u32_at(&mut img, opt + 96 + 4 * 8 + 4, 16);

    img
}

/// Build a deterministic synthetic PE32+ (`0x20B`) .NET assembly containing:
/// - `IMAGE_COR20_HEADER` (`DataDir[14]`)
/// - `BSJB` metadata with `#Strings` and `#~` (`Module`, `Assembly`, `ManifestResource`)
/// - Two embedded resources (one `0xBEEFCACE` `.resources`, one raw binary)
pub fn build_synthetic_pe64_dotnet() -> Vec<u8> {
    let mut img = vec![0u8; 0x1200];
    img[0..2].copy_from_slice(&0x5A4Du16.to_le_bytes());
    write_u32_at(&mut img, 0x3C, 0x80);

    write_u32_at(&mut img, 0x80, 0x0000_4550);
    img[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // x64
    img[0x86..0x88].copy_from_slice(&2u16.to_le_bytes());
    write_u32_at(&mut img, 0x88, 1_710_000_000);
    img[0x94..0x96].copy_from_slice(&240u16.to_le_bytes()); // SizeOfOptionalHeader (PE32+)
    img[0x96..0x98].copy_from_slice(&0x2022u16.to_le_bytes());

    let opt = 0x98usize;
    img[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes()); // PE32+
    img[opt + 2] = 48;
    write_u32_at(&mut img, opt + 16, 0x2000);
    push_u64(&mut vec![], 0); // unused helper silence
    img[opt + 24..opt + 32].copy_from_slice(&0x0001_8000_0000u64.to_le_bytes());
    img[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes()); // Windows CUI
    write_u32_at(&mut img, opt + 108, 16);

    let sec_off = opt + 240;
    let sections: [SectionSpec<'_>; 2] = [
        (b".text\0\0\0", 0x800, 0x2000, 0x800, 0x400, 0x6000_0020),
        (b".reloc\0\0", 0x200, 0x4000, 0x200, 0xC00, 0x4200_0040),
    ];
    for (i, (name, vsz, va, rsz, rptr, ch)) in sections.iter().enumerate() {
        let s = sec_off + i * 40;
        img[s..s + 8].copy_from_slice(*name);
        write_u32_at(&mut img, s + 8, *vsz);
        write_u32_at(&mut img, s + 12, *va);
        write_u32_at(&mut img, s + 16, *rsz);
        write_u32_at(&mut img, s + 20, *rptr);
        write_u32_at(&mut img, s + 36, *ch);
    }

    // Build #Strings heap
    let mut strings = vec![0u8];
    let mod_off = strings.len() as u16;
    strings.extend_from_slice(b"Sample.Lib.dll\0");
    let asm_off = strings.len() as u16;
    strings.extend_from_slice(b"Sample.Lib\0");
    let res1_off = strings.len() as u16;
    strings.extend_from_slice(b"Sample.Lib.g.resources\0");
    let res2_off = strings.len() as u16;
    strings.extend_from_slice(b"Sample.Lib.payload.bin\0");
    pad_to(&mut strings, 4);

    // Build #~ stream (Module 0x00, Assembly 0x20, ManifestResource 0x28)
    let mut tables = Vec::new();
    push_u32(&mut tables, 0);
    tables.push(2); // Major
    tables.push(0); // Minor
    tables.push(0); // HeapSizes = all 2-byte indices
    tables.push(1);
    let valid_mask: u64 = (1u64 << 0x00) | (1u64 << 0x20) | (1u64 << 0x28);
    push_u64(&mut tables, valid_mask);
    push_u64(&mut tables, 0);
    push_u32(&mut tables, 1); // Module rows = 1
    push_u32(&mut tables, 1); // Assembly rows = 1
    push_u32(&mut tables, 2); // ManifestResource rows = 2

    // Module row (10 bytes: Generation u16, Name u16, Mvid u16, EncId u16, EncBaseId u16)
    push_u16(&mut tables, 0);
    push_u16(&mut tables, mod_off);
    push_u16(&mut tables, 1);
    push_u16(&mut tables, 0);
    push_u16(&mut tables, 0);

    // Assembly row (22 bytes: HashAlg u32, Ver 4*u16, Flags u32, PubKey u16, Name u16, Culture u16)
    push_u32(&mut tables, 0x8004);
    push_u16(&mut tables, 1);
    push_u16(&mut tables, 2);
    push_u16(&mut tables, 3);
    push_u16(&mut tables, 4);
    push_u32(&mut tables, 0);
    push_u16(&mut tables, 0);
    push_u16(&mut tables, asm_off);
    push_u16(&mut tables, 0);

    // Embedded resources blob (2 resources)
    let mut res_blob = Vec::new();
    let res1_payload = [0xCE, 0xCA, 0xEF, 0xBE, 1, 0, 0, 0]; // 0xBEEFCACE
    let res1_blob_off = res_blob.len() as u32;
    push_u32(&mut res_blob, res1_payload.len() as u32);
    res_blob.extend_from_slice(&res1_payload);

    let res2_payload = b"HELLO_DOTNET_BIN";
    let res2_blob_off = res_blob.len() as u32;
    push_u32(&mut res_blob, res2_payload.len() as u32);
    res_blob.extend_from_slice(res2_payload);

    // ManifestResource rows (12 bytes each: Offset u32, Flags u32, Name u16, Impl u16)
    push_u32(&mut tables, res1_blob_off);
    push_u32(&mut tables, 1); // Public
    push_u16(&mut tables, res1_off);
    push_u16(&mut tables, 0);

    push_u32(&mut tables, res2_blob_off);
    push_u32(&mut tables, 2); // Private
    push_u16(&mut tables, res2_off);
    push_u16(&mut tables, 0);
    pad_to(&mut tables, 4);

    // Build BSJB metadata root
    let mut bsjb = Vec::new();
    push_u32(&mut bsjb, 0x424A_5342);
    push_u16(&mut bsjb, 1);
    push_u16(&mut bsjb, 1);
    push_u32(&mut bsjb, 0);
    let ver_str = b"v4.0.30319\0\0";
    push_u32(&mut bsjb, ver_str.len() as u32);
    bsjb.extend_from_slice(ver_str);
    push_u16(&mut bsjb, 0);
    push_u16(&mut bsjb, 2); // 2 streams: #~ and #Strings

    let header_end_est = bsjb.len() + (8 + 4) + (8 + 12);
    let tables_off = header_end_est as u32;
    push_u32(&mut bsjb, tables_off);
    push_u32(&mut bsjb, tables.len() as u32);
    bsjb.extend_from_slice(b"#~\0\0");

    let strings_off = tables_off + tables.len() as u32;
    push_u32(&mut bsjb, strings_off);
    push_u32(&mut bsjb, strings.len() as u32);
    bsjb.extend_from_slice(b"#Strings\0\0\0\0");

    assert_eq!(bsjb.len(), header_end_est);
    bsjb.extend_from_slice(&tables);
    bsjb.extend_from_slice(&strings);

    // Place COR20 header at file 0x400 (RVA 0x2000), BSJB at file 0x460 (RVA 0x2060), Res at file 0x600 (RVA 0x2200)
    let cor_off = 0x400usize;
    write_u32_at(&mut img, cor_off, 72); // cb
    img[cor_off + 4..cor_off + 6].copy_from_slice(&2u16.to_le_bytes());
    img[cor_off + 6..cor_off + 8].copy_from_slice(&5u16.to_le_bytes());
    write_u32_at(&mut img, cor_off + 8, 0x2060); // MetaData RVA
    write_u32_at(&mut img, cor_off + 12, bsjb.len() as u32);
    write_u32_at(&mut img, cor_off + 16, 1); // ILONLY
    write_u32_at(&mut img, cor_off + 24, 0x2200); // Resources RVA
    write_u32_at(&mut img, cor_off + 28, res_blob.len() as u32);

    img[0x460..0x460 + bsjb.len()].copy_from_slice(&bsjb);
    img[0x600..0x600 + res_blob.len()].copy_from_slice(&res_blob);

    // DataDir[14] = COM Descriptor
    write_u32_at(&mut img, opt + 112 + 14 * 8, 0x2000);
    write_u32_at(&mut img, opt + 112 + 14 * 8 + 4, 72);

    img
}

/// Create a synthetic GAC directory tree in `root` and return the path to the synthetic `.NET` DLL.
pub fn create_synthetic_gac_tree(root: &Path) -> Sys2RustResult<PathBuf> {
    let dir = root
        .join("GAC_MSIL")
        .join("Sample.Lib")
        .join("v4.0_1.2.3.4__0123456789abcdef");
    fs::create_dir_all(&dir)?;
    let dll_path = dir.join("Sample.Lib.dll");
    fs::write(&dll_path, build_synthetic_pe64_dotnet())?;
    Ok(dll_path)
}
