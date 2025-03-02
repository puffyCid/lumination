use crate::error::LuminationError;
use log::error;
use std::mem::zeroed;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};

pub(crate) struct WindowsProcs {
    pub(crate) pid: u32,
    pub(crate) parent: u32,
    pub(crate) name: String,
    pub(crate) path: String,
}

pub(crate) fn list_procs() -> Result<Vec<WindowsProcs>, LuminationError> {
    #[allow(unsafe_code)]
    unsafe {
        let handle = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(result) => result,
            Err(err) => {
                error!("[lumination] Could not get handle to snapshot: {err:?}");
                return Err(LuminationError::Procs);
            }
        };

        let mut process = zeroed::<PROCESSENTRY32W>();
        process.dwSize = match u32::try_from(size_of::<PROCESSENTRY32W>()) {
            Ok(result) => result,
            Err(err) => {
                error!("[lumination] Could not get size of process entry: {err:?}");
                return Err(LuminationError::Procs);
            }
        };

        if Process32FirstW(handle, &mut process).is_ok() {
            while Process32NextW(handle, &mut process).is_ok() {
                println!("{:?}", process);
            }
        }
    };

    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::list_procs;

    #[test]
    fn test_list_procs() {
        let status = list_procs().unwrap();
    }
}
