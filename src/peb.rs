use std::arch::asm;

use windows_sys::Win32::Foundation::UNICODE_STRING;
use windows_sys::Win32::System::Kernel::STRING;
use windows_sys::Win32::System::Threading::{PEB_LDR_DATA, PPS_POST_PROCESS_INIT_ROUTINE};

/// Returns a reference to the PEB.
///
/// returns: &'static PEB
pub fn get_peb() -> &'static PEB {
    unsafe {
        let peb: *const PEB;
        #[cfg(target_arch = "x86")]
        asm!(
            "mov {}, fs:[0x30]",
            lateout(reg) peb,
            options(pure, nomem, preserves_flags, nostack),
        );
        #[cfg(target_arch = "x86_64")]
        asm!(
            "mov {}, gs:[0x60]",
            lateout(reg) peb,
            options(pure, nomem, preserves_flags, nostack),
        );
        &*peb
    }
}

pub const FLG_HEAP_ENABLE_TAIL_CHECK: u32 = 0x10;
pub const FLG_HEAP_ENABLE_FREE_CHECK: u32 = 0x20;
pub const FLG_HEAP_VALIDATE_PARAMETERS: u32 = 0x40;

#[repr(C)]
pub struct PEB {
    pub InheritedAddressSpace: u8,
    pub ReadImageFileExecOptions: u8,
    pub BeingDebugged: u8,
    pub BitField: u8,
    pub Mutant: *mut std::ffi::c_void,
    pub ImageBaseAddress: *mut std::ffi::c_void,
    pub Ldr: *mut PEB_LDR_DATA,
    pub ProcessParameters: *mut RTL_USER_PROCESS_PARAMETERS,
    pub SubSystemData: *mut std::ffi::c_void,
    pub ProcessHeap: *mut std::ffi::c_void,
    pub FastPebLock: *mut std::ffi::c_void,
    pub AtlThunkSListPtr: *mut std::ffi::c_void,
    pub IFEOKey: *mut std::ffi::c_void,
    pub CrossProcessFlags: u32,
    pub KernelCallbackTable: *mut std::ffi::c_void,
    pub SystemReserved: u32,
    pub AtlThunkSListPtr32: u32,
    pub ApiSetMap: *mut std::ffi::c_void,
    pub TlsExpansionCounter: u32,
    pub TlsBitmap: *mut std::ffi::c_void,
    pub TlsBitmapBits: [u32; 2],
    pub ReadOnlySharedMemoryBase: *mut std::ffi::c_void,
    pub SharedData: *mut std::ffi::c_void,
    pub ReadOnlyStaticServerData: *mut std::ffi::c_void,
    pub AnsiCodePageData: *mut std::ffi::c_void,
    pub OemCodePageData: *mut std::ffi::c_void,
    pub UnicodeCaseTableData: *mut std::ffi::c_void,
    pub NumberOfProcessors: u32,
    pub NtGlobalFlag: u32,
    pub CriticalSectionTimeout: u64,
    pub HeapSegmentReserve: usize,
    pub HeapSegmentCommit: usize,
    pub HeapDeCommitTotalFreeThreshold: usize,
    pub HeapDeCommitFreeBlockThreshold: usize,
    pub NumberOfHeaps: u32,
    pub MaximumNumberOfHeaps: u32,
    pub ProcessHeaps: usize,
    pub GdiSharedHandleTable: *mut std::ffi::c_void,
    pub ProcessStarterHelper: *mut std::ffi::c_void,
    pub GdiDCAttributeList: u32,
    pub LoaderLock: *mut std::ffi::c_void,
    pub OSSMajorVersion: u32,
    pub OSMinorVersion: u32,
    pub OSBuildNumber: u16,
    pub OSCSDVersion: u16,
    pub OSPlatformId: u32,
    pub ImageSubsystem: u32,
    pub ImageSubsystemMajorVersion: u32,
    pub ImageSubsystemMinorVersion: u32,
    pub ActiveProcessAffinityMask: u64,
    pub GdiHandleBuffer: [u32; 0x3C],
    pub PostProcessInitRoutine: PPS_POST_PROCESS_INIT_ROUTINE,
    pub TlsExpansionBitmap: *mut std::ffi::c_void,
    pub TlsExpansionBitmapBits: [u32; 0x20],
    pub SessionId: u32,
}

#[repr(C)]
pub struct RTL_USER_PROCESS_PARAMETERS {
    pub MaximumLength: u32,
    pub Length: u32,
    pub Flags: u32,
    pub DebugFlags: u32,
    pub ConsoleHandle: *mut std::ffi::c_void,
    pub ConsoleFlags: u32,
    pub StandardInput: *mut std::ffi::c_void,
    pub StandardOutput: *mut std::ffi::c_void,
    pub StandardError: *mut std::ffi::c_void,
    pub CurrentDirectory: CURDIR,
    pub DllPath: UNICODE_STRING,
    pub ImagePathName: UNICODE_STRING,
    pub CommandLine: UNICODE_STRING,
    pub Environment: *mut std::ffi::c_void,
    pub StartingX: u32,
    pub StartingY: u32,
    pub CountX: u32,
    pub CountY: u32,
    pub CountCharsX: u32,
    pub CountCharsY: u32,
    pub FillAttribute: u32,
    pub WindowFlags: u32,
    pub ShowWindowFlags: u32,
    pub WindowTitle: UNICODE_STRING,
    pub DesktopInfo: UNICODE_STRING,
    pub ShellInfo: UNICODE_STRING,
    pub RuntimeData: UNICODE_STRING,
    pub CurrentDirectories: [RTL_DRIVE_LETTER_CURDIR; 0x20],
    pub EnvironmentSize: usize,
    pub EnvironmentVersion: usize,
    pub PackageDependencyData: *mut std::ffi::c_void,
    pub ProcessGroupId: u32,
    pub LoaderThreads: u32,
    pub RedirectionDllName: UNICODE_STRING,
    pub HeapPartitionName: UNICODE_STRING,
    pub DefaultThreadpoolCpuSetMasks: *mut core::ffi::c_void,
    pub DefaultThreadpoolCpuSetMaskCount: u32,
    pub DefaultThreadpoolThreadMaximum: u32,
}

#[repr(C)]
pub struct CURDIR {
    pub DosPath: UNICODE_STRING,
    pub Handle: *mut std::ffi::c_void,
}

#[repr(C)]
pub struct RTL_DRIVE_LETTER_CURDIR {
    pub Flags: u16,
    pub Length: u16,
    pub TimeStamp: u32,
    pub DosPath: STRING,
}
