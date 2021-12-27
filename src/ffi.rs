#![allow(non_camel_case_types)]
#![allow(unused)]
#![allow(non_snake_case)]

use crate::DWORD;

pub type LPVOID = *mut std::os::raw::c_void;

pub type SIZE_T = usize;

pub type BOOL = bool;
pub type HANDLE = *const std::os::raw::c_void;
pub type LPCSTR = *const u8;
pub type HMODULE = *const std::os::raw::c_void;


/// https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
pub mod AllocationType {
    use crate::DWORD;

    pub const MEM_COMMIT: DWORD = 0x00001000;
    pub const MEM_RESERVE: DWORD = 0x00002000;
    pub const MEM_RESET: DWORD = 0x00080000;
    pub const MEM_RESET_UNDO: DWORD = 0x1000000;

    // This parameter can also specify the following values as indicated.

    pub const MEM_LARGE_PAGES: DWORD = 0x20000000;
    pub const MEM_PHYSICAL: DWORD = 0x00400000;
    pub const MEM_TOP_DOWN: DWORD = 0x00100000;
    pub const MEM_WRITE_WATCH: DWORD = 0x00200000;
}

/// https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
pub mod Protect {
    use crate::DWORD;

    pub const PAGE_EXECUTE: DWORD = 0x10;
    pub const PAGE_EXECUTE_READ: DWORD = 0x20;
    pub const PAGE_EXECUTE_READWRITE: DWORD = 0x40;
    pub const PAGE_EXECUTE_WRITECOPY: DWORD = 0x80;
    pub const PAGE_NOACCESS: DWORD = 0x01;
    pub const PAGE_READONLY: DWORD = 0x02;
    pub const PAGE_READWRITE: DWORD = 0x04;
    pub const PAGE_WRITECOPY: DWORD = 0x08;
    pub const PAGE_TARGETS_INVALID: DWORD = 0x40000000;
    pub const PAGE_TARGETS_NO_UPDATE: DWORD = 0x40000000;

    // The following are modifiers that can be used in addition to the options provided in the previous table, except as noted.

    pub const PAGE_GUARD: DWORD = 0x100;
    pub const PAGE_NOCACHE: DWORD = 0x200;
    pub const PAGE_WRITECOMBINE: DWORD = 0x400;
}


/// https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfreeex
pub mod FreeType {
    use crate::DWORD;

    pub const MEM_DECOMMIT: DWORD = 0x00004000;
    pub const MEM_RELEASE: DWORD = 0x00008000;

    // When using MEM_RELEASE, this parameter can additionally specify one of the following values.

    pub const MEM_COALESCE_PLACEHOLDERS: DWORD = 0x00000001;
    pub const MEM_PRESERVE_PLACEHOLDER: DWORD = 0x00000002;
}


#[link(name = "Kernel32", kind = "dylib")]
extern "system" {

    /// https://docs.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror
    /// ```
    /// _Post_equals_last_error_ DWORD GetLastError();
    /// ```
    pub fn GetLastError() -> DWORD;

    /// https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
    /// ```
    /// LPVOID VirtualAlloc(
    ///   [in, optional] LPVOID lpAddress,
    ///   [in]           SIZE_T dwSize,
    ///   [in]           DWORD  flAllocationType,
    ///   [in]           DWORD  flProtect
    /// );
    /// ```
    pub fn VirtualAlloc(
        lpAddress: LPVOID,
        dwSize: usize,
        flAllocationType: DWORD,
        flProtect: DWORD,
    ) -> LPVOID;

    ///
    /// https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfree
    /// ```
    /// BOOL VirtualFree(
    ///  [in] LPVOID lpAddress,
    ///   [in] SIZE_T dwSize,
    ///   [in] DWORD  dwFreeType
    /// );
    /// ```
    pub fn VirtualFree(lpAddress: LPVOID, dw_size: SIZE_T, dwFreeType: DWORD) -> BOOL;

    /// https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
    /// ```
    /// LPVOID VirtualAllocEx(
    ///   [in]           HANDLE hProcess,
    ///   [in, optional] LPVOID lpAddress,
    ///   [in]           SIZE_T dwSize,
    ///   [in]           DWORD  flAllocationType,
    ///   [in]           DWORD  flProtect
    /// );
    /// ```
    pub fn VirtualAllocEx(
        hProcess: HANDLE,
        lpAddress: LPVOID,
        dwSize: SIZE_T,
        flAllocationType: DWORD,
        flProtect: DWORD,
    ) -> LPVOID;

    /// https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfreeex
    /// ```
    ///  BOOL VirtualFreeEx(
    ///    [in] HANDLE hProcess,
    ///    [in] LPVOID lpAddress,
    ///    [in] SIZE_T dwSize,
    ///    [in] DWORD  dwFreeType
    ///  );
    /// ```
    pub fn VirtualFreeEx(
        hProcess: HANDLE,
        lpAddress: LPVOID,
        dwSize: SIZE_T,
        dwFreeType: DWORD,
    ) -> LPVOID;

    /// https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya
    /// ```
    /// HMODULE LoadLibraryA(
    ///   [in] LPCSTR lpLibFileName
    /// );
    /// ```
    pub fn LoadLibraryA(lpLibFileName: LPCSTR) -> HMODULE;

    /// https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-freelibrary
    /// ```
    /// BOOL FreeLibrary(
    ///   [in] HMODULE hLibModule
    /// );
    /// ```
    pub fn FreeLibrary(hLibModule: HMODULE) -> BOOL;

    /// https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea
    /// ```
    /// HMODULE GetModuleHandleA(
    ///   [in, optional] LPCSTR lpModuleName
    /// );
    /// ```
    pub fn GetModuleHandleA(lpModuleName: LPCSTR) -> HMODULE;

    /// https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress
    /// ```
    /// FARPROC GetProcAddress(
    ///   [in] HMODULE hModule,
    ///   [in] LPCSTR  lpProcName
    /// );
    /// ```
    pub fn GetProcAddress(hModule: HMODULE, lpProcName: LPCSTR) -> LPVOID;

}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_library() {
        unsafe {
            
            let hModule = LoadLibraryA("User32.dll\0".as_ptr());

            assert!(!hModule.is_null());

            let hModule = GetModuleHandleA("User32.dll\0".as_ptr());

            assert!(!hModule.is_null());

            let MessageBoxA = GetProcAddress(hModule, "MessageBoxA\0".as_ptr());
  
            assert!(!MessageBoxA.is_null());

            // int MessageBoxA(
            //   [in, optional] HWND   hWnd,
            //   [in, optional] LPCSTR lpText,
            //   [in, optional] LPCSTR lpCaption,
            //   [in]           UINT   uType
            // );
            let MessageBoxA: extern "C" fn(LPVOID, LPCSTR, LPCSTR, u32) =
                std::mem::transmute(MessageBoxA);

            MessageBoxA(std::ptr::null_mut(), "Test\0".as_ptr(), "aaa\0".as_ptr(), 1);

            FreeLibrary(hModule);

            assert_eq!(0, GetLastError());
        }
    }

    #[test]
    fn test_ffi() {
        unsafe {
            let ptr = VirtualAlloc(
                std::ptr::null_mut(),
                1024,
                AllocationType::MEM_COMMIT,
                Protect::PAGE_READWRITE,
            );

            assert!(!ptr.is_null());

            let arr = ptr as *mut DWORD;

            *arr = 10;

            let arr = std::slice::from_raw_parts_mut(arr, 10);

            println!("{:?}", arr);

            assert!(VirtualFree(ptr, 0, FreeType::MEM_RELEASE));
        }
    }
}
