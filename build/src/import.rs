use std::io::Write;

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

use serpent::hash::hash_ci;

use crate::string::obfuscate_string;

pub fn obfuscate_imports(in_place: &mut [u8]) {
    let mut new_import_directory = vec![0; 20];
    let mut wipe = vec![];

    let import_data_directory;
    let iat_data_directory;
    {
        let input = &in_place[..];
        let dos_header = ImageDosHeader::parse(input).unwrap();
        let mut nt_header_offset = dos_header.nt_headers_offset().into();
        let (nt_headers, data_directories) =
            ImageNtHeaders64::parse(input, &mut nt_header_offset).unwrap();
        let file_header = nt_headers.file_header();
        let sections = file_header.sections(input, nt_header_offset).unwrap();

        import_data_directory = data_directories
            .get(IMAGE_DIRECTORY_ENTRY_IMPORT)
            .unwrap()
            .file_range(&sections)
            .unwrap();
        iat_data_directory = data_directories
            .get(IMAGE_DIRECTORY_ENTRY_IAT)
            .unwrap()
            .file_range(&sections)
            .unwrap();

        wipe.push(
            iat_data_directory.0 as usize..(iat_data_directory.0 + iat_data_directory.1) as usize,
        );

        // Iterate through all imports to wipe the names and map module names to
        // functions
        let mut module: &ImageImportDescriptor = unsafe {
            &*((&input[import_data_directory.0 as usize..][..import_data_directory.1 as usize])
                .as_ptr() as *const _)
        };
        let mut function_module_names: Vec<(usize, &str)> = Vec::new();
        while !module.is_null() {
            let (module_name_offset, _) = sections
                .pe_file_range_at(module.name.get(LittleEndian))
                .unwrap();
            let module_name_offset = module_name_offset as usize;
            let module_name_length = input[module_name_offset..]
                .iter()
                .position(|&c| c == 0)
                .unwrap();
            let module_name = &input[module_name_offset..][..module_name_length];
            wipe.push(module_name_offset..module_name_offset + module_name_length + 1);

            // Iterate through all functions
            let (function_offset, _) = sections
                .pe_file_range_at(module.original_first_thunk.get(LittleEndian))
                .unwrap();
            let mut function_rva =
                unsafe { &*((&input[function_offset as usize..]).as_ptr() as *const u64) };
            while *function_rva != 0 {
                function_module_names.push((
                    *function_rva as usize,
                    std::str::from_utf8(module_name).unwrap(),
                ));

                let (function_name_offset, _) =
                    sections.pe_file_range_at(*function_rva as u32).unwrap();
                let function_name_offset = function_name_offset as usize;
                let function_name_length = input[function_name_offset + 2..]
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap();
                wipe.push(function_name_offset..function_name_offset + function_name_length + 3);

                // Next function
                function_rva = unsafe { &*(function_rva as *const u64).add(1) };
            }

            // Next module
            module = unsafe { &*(module as *const ImageImportDescriptor).add(1) };
        }

        // Iterate through all modules
        let mut iat_directory =
            &input[iat_data_directory.0 as usize..][..iat_data_directory.1 as usize];
        while !iat_directory.is_empty() {
            let mut function_rva = iat_directory.read_u64::<byteorder::LittleEndian>().unwrap();
            let module_name = function_module_names
                .iter()
                .find(|(other_function_rva, _)| *other_function_rva == function_rva as usize)
                .unwrap()
                .1;
            println!("Module {}", module_name);

            // Write module hash if its an always-loaded module or obfuscated name
            match module_name {
                "ntdll.dll" | "kernel32.dll" => {
                    new_import_directory.push(0xFF - 1);
                    new_import_directory
                        .extend_from_slice(&hash_ci(module_name.as_bytes()).to_le_bytes());
                }
                _ => {
                    new_import_directory.push(0xFF - module_name.len() as u8);
                    new_import_directory.extend_from_slice(&obfuscate_string(module_name));
                }
            }

            // Iterate through all functions
            while function_rva != 0 {
                let (function_name_offset, _) =
                    sections.pe_file_range_at(function_rva as u32).unwrap();
                let function_name_offset = function_name_offset as usize;
                let function_name_length = input[function_name_offset + 2..]
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap();
                let function_name = &input[function_name_offset + 2..][..function_name_length];
                println!(
                    "Function {} {:08X}",
                    std::str::from_utf8(function_name).unwrap(),
                    hash_ci(function_name)
                );
                new_import_directory.extend_from_slice(&hash_ci(function_name).to_le_bytes());

                function_rva = iat_directory.read_u64::<byteorder::LittleEndian>().unwrap();
            }
            new_import_directory.extend_from_slice(&0u32.to_le_bytes());
        }

        new_import_directory.push(0xFF);
    }

    let mut rng = rand::thread_rng();
    let mut import_directory = &mut in_place[import_data_directory.0 as usize..]
        [..(import_data_directory.1 + iat_data_directory.1) as usize];
    import_directory.fill_with(|| rng.gen());
    import_directory.write_all(&new_import_directory).unwrap();
    for wipe in wipe {
        in_place[wipe].fill_with(|| rng.gen());
    }
}
