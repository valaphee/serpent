use std::{fs::OpenOptions, io::Write};

use crate::import::obfuscate_imports;

pub mod import;
pub mod string;

fn main() {
    let path = r#"C:\Users\valaphee\Documents\wgpu\target\release\wgpu-examples.exe"#;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let mut mmap = unsafe { memmap2::MmapMut::map_mut(&file) }.unwrap();
    obfuscate_imports(&mut mmap[..]);
    mmap.flush().unwrap();
}
