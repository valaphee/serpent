extern crate core;

use std::fs::OpenOptions;
use std::io::Write;

use object::coff::CoffHeader;
use object::pe::{
    ImageDosHeader, ImageImportDescriptor, ImageNtHeaders64, IMAGE_DIRECTORY_ENTRY_IAT,
    IMAGE_DIRECTORY_ENTRY_IMPORT,
};
use object::read::pe::ImageNtHeaders;
use object::LittleEndian;
use rand::Rng;

use malebolge::hash::fnv1a_ci;

fn main() {
    let path = r#"target\x86_64-pc-windows-msvc\release\examples\hello_world.exe"#;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let mut mmap = unsafe { memmap2::MmapMut::map_mut(&file) }.unwrap();
    import_obfuscation_v1(&mut mmap[..]);
    mmap.flush().unwrap();
}

fn string_obfuscation_v1(input: &[u8]) -> Vec<u8> {
    let length = input.iter().position(|&c| c == 0).unwrap();
    let value = &input[..=length];
    let key = value[rand::thread_rng().gen_range(0..length)];
    value.iter().map(|&c| c ^ key).collect()
}

fn import_obfuscation_v1(in_place: &mut [u8]) {
    let mut replace = vec![0; 20];
    let mut wipe = vec![];
    let import_directory;
    let import_address_table_directory;
    {
        let input = &in_place[..];
        let dos_header = ImageDosHeader::parse(input).unwrap();
        let mut nt_header_offset = dos_header.nt_headers_offset().into();
        let (nt_headers, data_directories) =
            ImageNtHeaders64::parse(input, &mut nt_header_offset).unwrap();
        let file_header = nt_headers.file_header();
        let sections = file_header.sections(input, nt_header_offset).unwrap();

        import_directory = data_directories
            .get(IMAGE_DIRECTORY_ENTRY_IMPORT)
            .unwrap()
            .file_range(&sections)
            .unwrap();
        import_address_table_directory = data_directories
            .get(IMAGE_DIRECTORY_ENTRY_IAT)
            .unwrap()
            .file_range(&sections)
            .unwrap();

        let mut import_descriptor: &ImageImportDescriptor = unsafe {
            &*((&input[import_directory.0 as usize..][..import_directory.1 as usize]).as_ptr()
                as *const _)
        };
        while !import_descriptor.is_null() {
            let (name_offset, _) = sections
                .pe_file_range_at(import_descriptor.name.get(LittleEndian))
                .unwrap();
            let name_offset = name_offset as usize;
            let name_length = input[name_offset..].iter().position(|&c| c == 0).unwrap();
            let name = &input[name_offset..][..name_length];
            println!("Module {}", std::str::from_utf8(name).unwrap());
            match name {
                b"ntdll.dll" | b"kernel32.dll" => {
                    replace.push(0xFF - 1);
                    replace.extend_from_slice(&fnv1a_ci(name).to_le_bytes());
                }
                _ => {
                    replace.push(0xFF - name_length as u8);
                    replace.extend_from_slice(&string_obfuscation_v1(&input[name_offset..]));
                }
            }
            wipe.push(name_offset..name_offset + name_length + 1);

            let (thunk_offset, _) = sections
                .pe_file_range_at(import_descriptor.original_first_thunk.get(LittleEndian))
                .unwrap();
            let mut thunk = unsafe { &*((&input[thunk_offset as usize..]).as_ptr() as *const u64) };
            while *thunk != 0 {
                let (name_offset, _) = sections.pe_file_range_at(*thunk as u32).unwrap();
                let name_offset = name_offset as usize;
                let name_length = input[name_offset + 2..]
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap();
                let name = &input[name_offset + 2..][..name_length];
                println!("Function {}", std::str::from_utf8(name).unwrap());
                replace.extend_from_slice(&fnv1a_ci(name).to_le_bytes());
                wipe.push(name_offset..name_offset + name_length + 3);

                thunk = unsafe { &*(thunk as *const u64).add(1) };
            }
            replace.extend_from_slice(&0u32.to_le_bytes());

            import_descriptor =
                unsafe { &*(import_descriptor as *const ImageImportDescriptor).add(1) };
        }
        replace.push(0xFF);
    }

    let mut rng = rand::thread_rng();
    let mut import_directory = &mut in_place[import_directory.0 as usize..]
        [..(import_directory.1 + import_address_table_directory.1) as usize];
    import_directory.fill_with(|| rng.gen());
    import_directory.write_all(&replace).unwrap();
    for wipe in wipe {
        in_place[wipe].fill_with(|| rng.gen());
    }
}
