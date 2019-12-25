#[macro_use]
extern crate clap;
use clap::{App, Arg};
extern crate winapi;
use std::ffi::CString;
use std::ptr::{null, null_mut};
use widestring::U16String;
use winapi::shared::minwindef::DWORD;
use winapi::shared::minwindef::FALSE;
use winapi::shared::minwindef::LPVOID;
use winapi::shared::ntdef::NULL;
use winapi::um::fileapi::GetFullPathNameW;
use winapi::um::libloaderapi::GetModuleHandleW;
use winapi::um::libloaderapi::GetProcAddress;
use winapi::um::memoryapi::VirtualAllocEx;
use winapi::um::memoryapi::WriteProcessMemory;
use winapi::um::minwinbase::PTHREAD_START_ROUTINE;
use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
use winapi::um::processthreadsapi::CreateRemoteThread;
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::winnt::LPWSTR;
use winapi::um::winnt::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PROCESS_CREATE_THREAD,
    PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
};

unsafe extern "system" fn wat(lpThreadParameter: LPVOID) -> DWORD {
    0u32
}

fn main() {
    let matches = App::new("DLL Injection")
        .arg(
            Arg::with_name("PID")
                .help("PID to inject into")
                .takes_value(true)
                .value_name("PID"),
        )
        .get_matches();

    let pid = value_t!(matches, "PID", u32).unwrap_or(1);

    unsafe {
        // open process
        let sys = OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ,
            FALSE,
            pid,
        );

        // allocate memory

        let dll_name: U16String = U16String::from_str("x.dll.\0");
        let lp_module_name = CString::new("LoadLibraryA").expect("failed");

        let null_x = null_mut();

        let dll_path: LPWSTR = Vec::with_capacity(128).as_mut_ptr();
        let size = GetFullPathNameW(
            dll_name.as_ptr(),
            10u32,
            dll_path, //Output to save the full DLL path
            null_x,
        );

        let dllPathAddr = VirtualAllocEx(
            sys,
            NULL,
            size as usize,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        );

        WriteProcessMemory(sys, dllPathAddr, NULL, dll_path as usize, null_mut());

        // Determine starting address
        let jmp_addr = GetProcAddress(GetModuleHandleW(dll_name.as_ptr()), lp_module_name.as_ptr());

        let mut sec_handle = SECURITY_ATTRIBUTES {
            nLength: 0,
            bInheritHandle: FALSE,
            lpSecurityDescriptor: NULL,
        };

        let no_idea: PTHREAD_START_ROUTINE = Some(wat);
        let mut null_wat = Vec::new();
        // start dll
        CreateRemoteThread(
            sys,
            &mut sec_handle,
            0,
            no_idea,
            NULL,
            0,
            null_wat.as_mut_ptr(),
        );
    }
}
