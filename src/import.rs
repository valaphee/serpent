use std::intrinsics::volatile_load;

use byteorder::{LittleEndian, ReadBytesExt};
use windows_sys::core::PCSTR;
use windows_sys::Win32::Foundation::{BOOL, HMODULE};
use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_DATA_DIRECTORY, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IAT,
    IMAGE_DIRECTORY_ENTRY_IMPORT,
};
use windows_sys::Win32::System::Kernel::LIST_ENTRY;
use windows_sys::Win32::System::Memory::{PAGE_PROTECTION_FLAGS, PAGE_READWRITE};
use windows_sys::Win32::System::SystemServices::{
    DLL_PROCESS_ATTACH, IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY,
};
use windows_sys::Win32::System::WindowsProgramming::LDR_DATA_TABLE_ENTRY;

use crate::hash::{fnv1a_ci, fnv1a_wci};
use crate::peb::get_peb;

/// Search for a module with the given hash by using the PEB's LDR
/// InMemoryOrderModuleList and hashing the FullDllName.
///
/// # Arguments
///
/// * `module_hash`: FNV1a hash of the module's name, lower-case
///
/// returns: Option<isize>
#[inline(always)]
pub fn get_module(module_hash: u32) -> Option<HMODULE> {
    unsafe {
        let peb = get_peb();

        let mut ldr_in_memory_order_module_list_entry =
            &(*peb.Ldr).InMemoryOrderModuleList as *const LIST_ENTRY;
        while ldr_in_memory_order_module_list_entry != (*peb.Ldr).InMemoryOrderModuleList.Blink {
            let ldr_data_table_entry =
                &*(ldr_in_memory_order_module_list_entry as *const LDR_DATA_TABLE_ENTRY);

            let name = std::slice::from_raw_parts(
                ldr_data_table_entry.FullDllName.Buffer as *const u16,
                ldr_data_table_entry.FullDllName.Length as usize / 2,
            );
            let hash = fnv1a_wci(name);
            if hash == module_hash {
                return Some(ldr_data_table_entry.Reserved2[0] as isize);
            }

            ldr_in_memory_order_module_list_entry = (*ldr_in_memory_order_module_list_entry).Flink
        }

        None
    }
}

/// Search for a module with the given hash by using the PEB's LDR
/// InMemoryOrderModuleList and hashing the FullDllName without the file suffix.
///
/// # Arguments
///
/// * `module_hash`: FNV1a hash of the module's name without extension, lower-case
///
/// returns: Option<isize>
#[inline(always)]
pub fn get_module_without_extension(module_hash: u32) -> Option<HMODULE> {
    unsafe {
        let peb = get_peb();

        let mut ldr_in_memory_order_module_list_entry =
            &(*peb.Ldr).InMemoryOrderModuleList as *const LIST_ENTRY;
        while ldr_in_memory_order_module_list_entry != (*peb.Ldr).InMemoryOrderModuleList.Blink {
            let ldr_data_table_entry =
                &*(ldr_in_memory_order_module_list_entry as *const LDR_DATA_TABLE_ENTRY);

            let name = if ldr_data_table_entry.FullDllName.Length == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(
                    ldr_data_table_entry.FullDllName.Buffer as *const u16,
                    (ldr_data_table_entry.FullDllName.Length as usize / 2) - 4,
                )
            };
            let hash = fnv1a_wci(name);
            if hash == module_hash {
                return Some(ldr_data_table_entry.Reserved2[0] as isize);
            }

            ldr_in_memory_order_module_list_entry = (*ldr_in_memory_order_module_list_entry).Flink
        }

        None
    }
}

/// Search for a function inside the given module's export table.
///
/// # Arguments
///
/// * `module`: Module base address
/// * `function_hash`: FNV1a hash of the exported name, lower-case
///
/// returns: *const c_void
///
/// # Safety
///
/// `module` must point to a currently loaded module
#[inline(always)]
pub unsafe fn get_function(module: HMODULE, function_hash: u32) -> Option<*const std::ffi::c_void> {
    let dos_headers = &*(module as *const IMAGE_DOS_HEADER);
    #[cfg(target_arch = "x86")]
    let nt_headers = &*((module + dos_headers.e_lfanew as isize)
        as *const windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32);
    #[cfg(target_arch = "x86_64")]
    let nt_headers = &*((module + dos_headers.e_lfanew as isize)
        as *const windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64);
    let export_data_directory = &*(&nt_headers.OptionalHeader.DataDirectory
        [IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
        as *const IMAGE_DATA_DIRECTORY);
    let export_directory = &*((module + export_data_directory.VirtualAddress as isize)
        as *const IMAGE_EXPORT_DIRECTORY);

    let functions = std::slice::from_raw_parts(
        (module + export_directory.AddressOfFunctions as isize) as *const u32,
        export_directory.NumberOfFunctions as usize,
    );
    let names = std::slice::from_raw_parts(
        (module + export_directory.AddressOfNames as isize) as *const u32,
        export_directory.NumberOfNames as usize,
    );
    let name_ordinals = std::slice::from_raw_parts(
        (module + export_directory.AddressOfNameOrdinals as isize) as *const u16,
        export_directory.NumberOfNames as usize,
    );

    // Go through all exports
    for (&name, &name_ordinal) in names.iter().zip(name_ordinals) {
        let name = (module + name as isize) as *const u8;
        let mut name_end = name;
        while *name_end != 0 {
            name_end = name_end.add(1)
        }
        let name_length = name_end.offset_from(name) as usize;

        // Generate and compare hash
        let name = std::slice::from_raw_parts(name, name_length);
        let hash = fnv1a_ci(name);
        if hash == function_hash {
            let function_rva = functions[name_ordinal as usize];
            let function = (module + function_rva as isize) as *const std::ffi::c_void;

            // Check if function rva is inside the export data directory which indicates a forward
            if function_rva >= export_data_directory.VirtualAddress
                && function_rva < export_data_directory.VirtualAddress + export_data_directory.Size
            {
                let mut function = std::slice::from_raw_parts(
                    function as *const u8,
                    (function_rva - export_data_directory.VirtualAddress
                        + export_data_directory.Size) as usize,
                );
                let forward_module_name_length = function.iter().position(|&c| c == b'.').unwrap();
                let forward_module =
                    get_module_without_extension(fnv1a_ci(&function[..forward_module_name_length]))
                        .unwrap();
                let forward_function_name_length = function.iter().position(|&c| c == 0).unwrap();
                let forward_function = get_function(
                    forward_module,
                    fnv1a_ci(
                        &function[forward_module_name_length + 1..forward_function_name_length],
                    ),
                )
                .unwrap();
                return Some(forward_function);
            } else {
                return Some(function);
            }
        }
    }

    None
}

#[no_mangle]
pub unsafe extern "system" fn import_obfuscation_v1(
    DllHandle: *const std::ffi::c_void,
    dwReason: u32,
    Reserved: *const std::ffi::c_void,
) {
    if dwReason != DLL_PROCESS_ATTACH {
        return;
    }

    let kernel32 = get_module(fnv1a_ci(b"kernel32.dll")).unwrap();
    let virtual_protect: VirtualProtect = std::mem::transmute(
        get_function(
            kernel32,
            fnv1a_ci(b"VirtualProtect"),
        )
        .unwrap(),
    );
    let load_library_a: LoadLibraryA = std::mem::transmute(
        get_function(
            kernel32,
            fnv1a_ci(b"LoadLibraryA"),
        )
        .unwrap(),
    );

    let module = DllHandle as HMODULE;
    let dos_headers = &*(module as *const IMAGE_DOS_HEADER);
    #[cfg(target_arch = "x86")]
    let nt_headers = &*((module + dos_headers.e_lfanew as isize)
        as *const windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32);
    #[cfg(target_arch = "x86_64")]
    let nt_headers = &*((module + dos_headers.e_lfanew as isize)
        as *const windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64);
    let import_data_directory = &*(&nt_headers.OptionalHeader.DataDirectory
        [IMAGE_DIRECTORY_ENTRY_IMPORT as usize]
        as *const IMAGE_DATA_DIRECTORY);
    let mut import_directory = std::slice::from_raw_parts_mut(
        (module + import_data_directory.VirtualAddress as isize + 20) as *mut u8,
        nt_headers.OptionalHeader.SizeOfImage as usize,
    );
    let iat_data_directory = &*(&nt_headers.OptionalHeader.DataDirectory
        [IMAGE_DIRECTORY_ENTRY_IAT as usize]
        as *const IMAGE_DATA_DIRECTORY);
    let mut iat_directory = std::slice::from_raw_parts_mut(
        (module + iat_data_directory.VirtualAddress as isize) as *mut u64,
        iat_data_directory.Size as usize,
    );

    let mut import_directory_protect = PAGE_READWRITE;
    let mut iat_directory_protect = PAGE_READWRITE;
    virtual_protect(
        import_directory.as_ptr() as *const _,
        import_data_directory.Size as usize,
        import_directory_protect,
        &mut import_directory_protect,
    );
    virtual_protect(
        iat_directory.as_ptr() as *const _,
        iat_directory.len(),
        iat_directory_protect,
        &mut iat_directory_protect,
    );

    let mut iat_directory_entry = 0;
    loop {
        let module_name_length = 0xFF - import_directory.read_u8().unwrap();
        let module = match module_name_length {
            0 => break,
            1 => {
                let module_hash = import_directory.read_u32::<LittleEndian>().unwrap();
                get_module(module_hash).unwrap()
            }
            _ => {
                let (xor_val, remaining) =
                    import_directory.split_at_mut(module_name_length as usize + 1);
                import_directory = remaining;

                let xor_val_mut =
                    std::slice::from_raw_parts_mut(xor_val.as_mut_ptr() as *mut u8, xor_val.len());
                let xor_key = *xor_val_mut.last().unwrap();
                for c in xor_val_mut {
                    *c ^= xor_key;
                }
                load_library_a(xor_val.as_ptr())
            }
        };

        loop {
            let function_hash = import_directory.read_u32::<LittleEndian>().unwrap();
            if function_hash == 0 {
                break;
            }

            iat_directory[iat_directory_entry] =
                get_function(module, function_hash).unwrap() as u64;
            iat_directory_entry += 1;
        }
        iat_directory_entry += 1;
    }

    virtual_protect(
        iat_directory.as_ptr() as *const _,
        iat_directory.len(),
        iat_directory_protect,
        &mut iat_directory_protect,
    );
    virtual_protect(
        import_directory.as_ptr() as *const _,
        import_data_directory.Size as usize,
        import_directory_protect,
        &mut import_directory_protect,
    );

    reference_tls_used();
    #[cfg(target_env = "msvc")]
    unsafe fn reference_tls_used() {
        extern "C" {
            static _tls_used: u8;
        }
        volatile_load(&_tls_used);
    }
    #[cfg(not(target_env = "msvc"))]
    unsafe fn reference_tls_used() {}
}

type VirtualProtect = unsafe extern "system" fn(
    lpaddress: *const ::core::ffi::c_void,
    dwsize: usize,
    flnewprotect: PAGE_PROTECTION_FLAGS,
    lpfloldprotect: *mut PAGE_PROTECTION_FLAGS,
) -> BOOL;
type LoadLibraryA = unsafe extern "system" fn(PCSTR) -> HMODULE;
