pub mod string;
pub mod import;

use std::{fs::OpenOptions, io::Write};

use byteorder::ReadBytesExt;
use object::{
    coff::CoffHeader,
    pe::{
        ImageDosHeader, ImageImportDescriptor, ImageNtHeaders64, IMAGE_DIRECTORY_ENTRY_IAT,
        IMAGE_DIRECTORY_ENTRY_IMPORT,
    },
    read::pe::ImageNtHeaders,
    LittleEndian,
};
use rand::Rng;

use serpent::hash::fnv1a_ci;
use crate::import::import_obfuscation_v1;

fn main() {
    let path = r#"C:\Users\valaphee\Documents\wgpu\target\release\wgpu-examples.exe"#;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let mut mmap = unsafe { memmap2::MmapMut::map_mut(&file) }.unwrap();
    import_obfuscation_v1(&mut mmap[..]);
    mmap.flush().unwrap();
}

