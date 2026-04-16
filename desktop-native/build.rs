fn main() {
    // Always regenerate icon.ico so file-explorer icon matches window icon exactly.
    // Both use: dark navy background (#0c1623) + teal circle (0,180,145).
    generate_ico("icon.ico");

    #[cfg(target_os = "windows")]
    {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("icon.ico");
        res.set("ProductName", "DevProxy");
        res.set("FileDescription", "DevProxy - 本地 HTTPS 反向代理工具");
        res.set("CompanyName", "DevProxy");
        res.compile().expect("Failed to compile Windows resources");
    }
}

/// Generate a PNG of `sz x sz` pixels: dark navy background + teal circle.
fn make_png(sz: u32) -> Vec<u8> {
    let cf = sz as f32 / 2.0;
    let r = cf - (sz as f32 * 0.06).max(2.0);
    let mut pixels = vec![0u8; (sz * sz * 4) as usize];
    for y in 0..sz {
        for x in 0..sz {
            let dx = x as f32 + 0.5 - cf;
            let dy = y as f32 + 0.5 - cf;
            let dist = (dx * dx + dy * dy).sqrt();
            let i = ((y * sz + x) * 4) as usize;
            if dist < r {
                pixels[i] = 0; pixels[i+1] = 180; pixels[i+2] = 145; pixels[i+3] = 255;
            } else {
                pixels[i] = 12; pixels[i+1] = 22; pixels[i+2] = 35; pixels[i+3] = 255;
            }
        }
    }
    // Encode as PNG using raw IDAT (deflate level 0 for simplicity via miniz)
    encode_png_raw(sz, sz, &pixels)
}

/// Minimal PNG encoder (no external deps – uses raw deflate via flate2 which is
/// already pulled in transitively, but we can't import it in build.rs easily).
/// Instead we write a completely uncompressed PNG (using non-compressed DEFLATE
/// blocks), which is valid and small enough for an icon.
fn encode_png_raw(w: u32, h: u32, rgba: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    // PNG signature
    out.extend_from_slice(&[137, 80, 78, 71, 13, 10, 26, 10]);
    // IHDR
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&w.to_be_bytes());
    ihdr.extend_from_slice(&h.to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]); // 8-bit RGB? No – use RGBA (color type 6)
    let mut ihdr2 = Vec::new();
    ihdr2.extend_from_slice(&w.to_be_bytes());
    ihdr2.extend_from_slice(&h.to_be_bytes());
    ihdr2.push(8);  // bit depth
    ihdr2.push(6);  // color type: RGBA
    ihdr2.extend_from_slice(&[0, 0, 0]); // compression, filter, interlace
    write_chunk(&mut out, b"IHDR", &ihdr2);
    // IDAT: raw image data with filter byte 0 per scanline
    let mut raw = Vec::new();
    for y in 0..h {
        raw.push(0); // filter type None
        let row_start = (y * w * 4) as usize;
        raw.extend_from_slice(&rgba[row_start..row_start + (w * 4) as usize]);
    }
    let compressed = deflate_no_compress(&raw);
    write_chunk(&mut out, b"IDAT", &compressed);
    // IEND
    write_chunk(&mut out, b"IEND", &[]);
    out
}

fn write_chunk(out: &mut Vec<u8>, tag: &[u8; 4], data: &[u8]) {
    let len = data.len() as u32;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(tag);
    out.extend_from_slice(data);
    let crc = crc32(tag, data);
    out.extend_from_slice(&crc.to_be_bytes());
}

fn crc32(tag: &[u8], data: &[u8]) -> u32 {
    // CRC32 table
    let mut table = [0u32; 256];
    for i in 0u32..256 {
        let mut c = i;
        for _ in 0..8 { c = if c & 1 != 0 { 0xedb88320 ^ (c >> 1) } else { c >> 1 }; }
        table[i as usize] = c;
    }
    let mut crc = 0xffffffff_u32;
    for &b in tag.iter().chain(data.iter()) {
        crc = table[((crc ^ b as u32) & 0xff) as usize] ^ (crc >> 8);
    }
    crc ^ 0xffffffff
}

/// Wrap uncompressed data in a valid DEFLATE/zlib stream (no compression, stored blocks).
fn deflate_no_compress(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    // zlib header: CM=8, CINFO=7, FCHECK makes multiple of 31
    out.push(0x78); out.push(0x01);
    // DEFLATE stored blocks (BTYPE=00), each block up to 65535 bytes
    let mut pos = 0;
    while pos < data.len() {
        let end = (pos + 65535).min(data.len());
        let is_last = end == data.len();
        out.push(if is_last { 1 } else { 0 }); // BFINAL | BTYPE=00
        let blen = (end - pos) as u16;
        out.extend_from_slice(&blen.to_le_bytes());
        out.extend_from_slice(&(!blen).to_le_bytes());
        out.extend_from_slice(&data[pos..end]);
        pos = end;
    }
    if data.is_empty() { out.extend_from_slice(&[1, 0, 0, 0xff, 0xff]); }
    // Adler-32 checksum
    let (mut s1, mut s2) = (1u32, 0u32);
    for &b in data { s1 = (s1 + b as u32) % 65521; s2 = (s2 + s1) % 65521; }
    let adler = (s2 << 16) | s1;
    out.extend_from_slice(&adler.to_be_bytes());
    out
}

fn generate_ico(path: &str) {
    let sizes: &[u32] = &[256, 48, 32, 16];
    let pngs: Vec<Vec<u8>> = sizes.iter().map(|&s| make_png(s)).collect();
    let n = sizes.len();
    let mut out = Vec::new();
    // ICO header
    out.extend_from_slice(&0u16.to_le_bytes()); // reserved
    out.extend_from_slice(&1u16.to_le_bytes()); // type = ICO
    out.extend_from_slice(&(n as u16).to_le_bytes());
    // Directory entries
    let header_size = 6 + 16 * n;
    let mut offset = header_size;
    for (i, &sz) in sizes.iter().enumerate() {
        let dim = if sz >= 256 { 0u8 } else { sz as u8 };
        out.push(dim); out.push(dim); out.push(0); out.push(0); // w,h,colors,reserved
        out.extend_from_slice(&1u16.to_le_bytes()); // planes
        out.extend_from_slice(&32u16.to_le_bytes()); // bpp
        out.extend_from_slice(&(pngs[i].len() as u32).to_le_bytes());
        out.extend_from_slice(&(offset as u32).to_le_bytes());
        offset += pngs[i].len();
    }
    for png in &pngs { out.extend_from_slice(png); }
    std::fs::write(path, &out).expect("Failed to write icon.ico");
}
