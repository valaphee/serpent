extern crate core;

use std::fs::OpenOptions;
use std::io::Write;
use std::ops::Range;
use byteorder::ReadBytesExt;

use object::coff::CoffHeader;
use object::pe::{
    ImageDosHeader, ImageImportDescriptor, ImageNtHeaders64, IMAGE_DIRECTORY_ENTRY_IAT,
    IMAGE_DIRECTORY_ENTRY_IMPORT,
};
use object::read::pe::ImageNtHeaders;
use object::LittleEndian;
use rand::Rng;

use serpent::hash::fnv1a_ci;
use serpent::import::{get_function, get_module, HMODULE};

type LoadLibraryA = unsafe extern "system" fn(*const u8) -> usize;

fn main() {
    //let a = get_module(fnv1a_ci(b"advapi32.dll")).unwrap();
    /*let kernel32 = get_module(fnv1a_ci(b"kernel32.dll")).unwrap();
    let load_library_a: LoadLibraryA = unsafe {
        std::mem::transmute(
            get_function(
                kernel32,
                fnv1a_ci(b"LoadLibraryA"),
            )
                .unwrap(),
        )
    };
    let a = unsafe {
        load_library_a(b"advapi32.dll\0".as_ptr())
    };
    let b = unsafe {
        load_library_a(b"cryptbase.dll\0".as_ptr())
    };
    println!("{}", b);
    let b = unsafe { get_function(a as HMODULE, 0x1C21CE99).unwrap() };
    return;*/

    let path = r#"C:\Users\valaphee\Documents\wgpu\target\release\wgpu-examples.exe"#;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let mut mmap = unsafe { memmap2::MmapMut::map_mut(&file) }.unwrap();
    //let mut mmap = std::fs::read(path).unwrap();
    import_obfuscation_v1(&mut mmap[..]);
    mmap.flush().unwrap();
}

fn string_obfuscation_v1(input: &str) -> Vec<u8> {
    let mut value = input.as_bytes().to_vec();
    let key = value[rand::thread_rng().gen_range(0..value.len())];
    value.push(0);
    for v in value.iter_mut() {
        *v = *v ^ key
    }
    value
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
        let mut iat_table = &input[import_address_table_directory.0 as usize..][..import_address_table_directory.1 as usize];
        let mut lap_ranges: Vec<(usize, &str)> = Vec::new();

        while !import_descriptor.is_null() {
            let (name_offset, _) = sections
                .pe_file_range_at(import_descriptor.name.get(LittleEndian))
                .unwrap();
            let name_offset = name_offset as usize;
            let name_length = input[name_offset..].iter().position(|&c| c == 0).unwrap();
            let name = &input[name_offset..][..name_length];
            /*println!("Module {}", std::str::from_utf8(name).unwrap());
            match name {
                b"ntdll.dll" | b"kernel32.dll" => {
                    replace.push(0xFF - 1);
                    replace.extend_from_slice(&fnv1a_ci(name).to_le_bytes());
                }
                _ => {
                    replace.push(0xFF - name_length as u8);
                    replace.extend_from_slice(&string_obfuscation_v1(&input[name_offset..]));
                }
            }*/
            wipe.push(name_offset..name_offset + name_length + 1);

            let (thunk_offset, _) = sections
                .pe_file_range_at(import_descriptor.original_first_thunk.get(LittleEndian))
                .unwrap();
            let mut thunk = unsafe { &*((&input[thunk_offset as usize..]).as_ptr() as *const u64) };
            while *thunk != 0 {
                lap_ranges.push((*thunk as usize, std::str::from_utf8(name).unwrap()));

                let (name_offset, _) = sections.pe_file_range_at(*thunk as u32).unwrap();
                let name_offset = name_offset as usize;
                let name_length = input[name_offset + 2..]
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap();
                let name = &input[name_offset + 2..][..name_length];
                //println!("Function {} {:08X}", std::str::from_utf8(name).unwrap(), fnv1a_ci(name));
                //replace.extend_from_slice(&fnv1a_ci(name).to_le_bytes());
                wipe.push(name_offset..name_offset + name_length + 3);

                thunk = unsafe { &*(thunk as *const u64).add(1) };
            }
            //replace.extend_from_slice(&0u32.to_le_bytes());

            import_descriptor =
                unsafe { &*(import_descriptor as *const ImageImportDescriptor).add(1) };
        }

        while !iat_table.is_empty() {
            let mut addr = iat_table.read_u64::<byteorder::LittleEndian>().unwrap();
            let lap_range = lap_ranges.iter().find(|&lap_range| lap_range.0 == addr as usize).unwrap();
            let name = lap_range.1;
            println!("Module {}", name);
            match name {
                "ntdll.dll" | "kernel32.dll" => {
                    replace.push(0xFF - 1);
                    replace.extend_from_slice(&fnv1a_ci(name.as_bytes()).to_le_bytes());
                }
                _ => {
                    replace.push(0xFF - name.len() as u8);
                    replace.extend_from_slice(&string_obfuscation_v1(name));
                }
            }
            while addr != 0 {
                let (name_offset, _) = sections.pe_file_range_at(addr as u32).unwrap();
                let name_offset = name_offset as usize;
                let name_length = input[name_offset + 2..]
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap();
                let name = &input[name_offset + 2..][..name_length];
                println!("Function {} {:08X}", std::str::from_utf8(name).unwrap(), fnv1a_ci(name));
                replace.extend_from_slice(&fnv1a_ci(name).to_le_bytes());

                addr = iat_table.read_u64::<byteorder::LittleEndian>().unwrap();
            }
            replace.extend_from_slice(&0u32.to_le_bytes());
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
