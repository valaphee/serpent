use core::{ffi, intrinsics::volatile_load, mem, mem::MaybeUninit, slice};

use byteorder::{LittleEndian, ReadBytesExt};
use windows_sys::core::PCSTR;
pub use windows_sys::Win32::{
    Foundation::{BOOL, HMODULE, MAX_PATH},
    System::{
        Diagnostics::Debug::{
            IMAGE_DATA_DIRECTORY, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IAT,
            IMAGE_DIRECTORY_ENTRY_IMPORT,
        },
        Kernel::LIST_ENTRY,
        Memory::{PAGE_PROTECTION_FLAGS, PAGE_READWRITE},
        SystemServices::{DLL_PROCESS_ATTACH, IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY},
        WindowsProgramming::LDR_DATA_TABLE_ENTRY,
    },
};

use crate::{
    hash::{hash_ci, hash_ci_ptr, hash_wci},
    peb::get_peb,
};

/// Search for a module with the given hash by using the PEB's LDR
/// InMemoryOrderModuleList and hashing the FullDllName.
///
/// # Arguments
///
/// * `module_hash`: Hash of the module's name, lower-case
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

            let name = slice::from_raw_parts(
                ldr_data_table_entry.FullDllName.Buffer as *const u16,
                ldr_data_table_entry.FullDllName.Length as usize / 2,
            );
            let hash = hash_wci(name);
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
/// * `module_hash`: FNV1a hash of the module's name without extension,
///   lower-case
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

            let name = if ldr_data_table_entry.FullDllName.Length <= 4 {
                &[]
            } else {
                slice::from_raw_parts(
                    ldr_data_table_entry.FullDllName.Buffer as *const u16,
                    (ldr_data_table_entry.FullDllName.Length as usize / 2) - 4,
                )
            };
            let hash = hash_wci(name);
            if hash == module_hash {
                return Some(ldr_data_table_entry.Reserved2[0] as isize);
            }

            ldr_in_memory_order_module_list_entry = (*ldr_in_memory_order_module_list_entry).Flink
        }

        None
    }
}

/// Search for a function with the given hash inside the module's export table.
///
/// # Arguments
///
/// * `module`: Module base address
/// * `function_hash`: Hash of the exported name, lower-case
///
/// returns: *const c_void
///
/// # Safety
///
/// `module` must point to a currently loaded module
#[inline(always)]
pub unsafe fn get_function(module: HMODULE, function_hash: u32) -> Option<*const ffi::c_void> {
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

    let function_rvas = slice::from_raw_parts(
        (module + export_directory.AddressOfFunctions as isize) as *const u32,
        export_directory.NumberOfFunctions as usize,
    );
    let function_names_rvas = slice::from_raw_parts(
        (module + export_directory.AddressOfNames as isize) as *const u32,
        export_directory.NumberOfNames as usize,
    );
    let function_name_ordinals = slice::from_raw_parts(
        (module + export_directory.AddressOfNameOrdinals as isize) as *const u16,
        export_directory.NumberOfNames as usize,
    );

    // Iterate through all exported functions
    for i in 0..function_names_rvas.len() {
        let function_name_rva = function_names_rvas[i];
        let function_name_ordinal = function_name_ordinals[i];

        // Generate and compare hashes
        let current_function_hash = hash_ci_ptr((module + function_name_rva as isize) as *const u8);
        if current_function_hash == function_hash {
            let function_rva = function_rvas[function_name_ordinal as usize];
            let function = (module + function_rva as isize) as *const ffi::c_void;

            // Check if the function rva is inside the export data directory which indicates
            // a forwarded function
            return if (export_data_directory.VirtualAddress
                ..export_data_directory.VirtualAddress + export_data_directory.Size)
                .contains(&function_rva)
            {
                let mut forward_module_name = slice::from_raw_parts(
                    function as *const u8,
                    (function_rva - export_data_directory.VirtualAddress
                        + export_data_directory.Size) as usize,
                );
                let forward_module_name_length =
                    forward_module_name.iter().position(|&c| c == b'.').unwrap();
                let forward_module = get_module_without_extension(hash_ci(
                    &forward_module_name[..forward_module_name_length],
                ))
                .unwrap_or_else(|| {
                    let load_library_a: LoadLibraryA = mem::transmute(get_function(
                            get_module(hash_ci(b"kernel32.dll")).unwrap(),
                            hash_ci(b"LoadLibraryA"),
                        )
                        .unwrap());

                    let mut forward_module_name_with_extension: [u8; MAX_PATH as usize] =
                        MaybeUninit::uninit().assume_init();
                    for n in 0..forward_module_name_length {
                        forward_module_name_with_extension[n] = forward_module_name[n];
                    }
                    forward_module_name_with_extension[forward_module_name_length] = b'.';
                    forward_module_name_with_extension[forward_module_name_length + 1] = b'd';
                    forward_module_name_with_extension[forward_module_name_length + 2] = b'l';
                    forward_module_name_with_extension[forward_module_name_length + 3] = b'l';
                    forward_module_name_with_extension[forward_module_name_length + 4] = b'\0';
                    load_library_a(forward_module_name_with_extension.as_ptr())
                });
                let forward_function_name_length =
                    forward_module_name.iter().position(|&c| c == 0).unwrap();
                let forward_function = get_function(
                    forward_module,
                    hash_ci(
                        &forward_module_name
                            [forward_module_name_length + 1..forward_function_name_length],
                    ),
                )
                .unwrap();
                Some(forward_function)
            } else {
                Some(function)
            };
        }
    }

    None
}

#[no_mangle]
pub unsafe extern "system" fn import_obfuscation_v1(
    DllHandle: *const ffi::c_void,
    dwReason: u32,
    Reserved: *const ffi::c_void,
) {
    if dwReason != DLL_PROCESS_ATTACH {
        return;
    }

    let kernel32 = get_module(hash_ci(b"kernel32.dll")).unwrap();
    let virtual_protect: VirtualProtect =
        mem::transmute(get_function(kernel32, hash_ci(b"VirtualProtect")).unwrap());
    let load_library_a: LoadLibraryA = mem::transmute(get_function(kernel32, hash_ci(b"LoadLibraryA")).unwrap());

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
    let mut import_directory = slice::from_raw_parts(
        (module + import_data_directory.VirtualAddress as isize + 20) as *mut u8,
        nt_headers.OptionalHeader.SizeOfImage as usize,
    );
    let iat_data_directory = &*(&nt_headers.OptionalHeader.DataDirectory
        [IMAGE_DIRECTORY_ENTRY_IAT as usize]
        as *const IMAGE_DATA_DIRECTORY);
    let mut iat_directory = slice::from_raw_parts_mut(
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
                    import_directory.split_at(module_name_length as usize + 1);
                import_directory = remaining;

                let xor_val_mut =
                    slice::from_raw_parts_mut(xor_val.as_ptr() as *mut u8, xor_val.len());
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

            iat_directory[iat_directory_entry] = mem::transmute(get_function(module, function_hash).unwrap());
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
    lpaddress: *const ffi::c_void,
    dwsize: usize,
    flnewprotect: PAGE_PROTECTION_FLAGS,
    lpfloldprotect: *mut PAGE_PROTECTION_FLAGS,
) -> BOOL;
type LoadLibraryA = unsafe extern "system" fn(PCSTR) -> HMODULE;
