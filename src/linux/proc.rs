use crate::error::LuminationError;
use glob::glob;
use log::error;
use std::{fs::read_link, path::PathBuf};

#[derive(Debug)]
pub(crate) struct ProcInfo {
    pub(crate) socket: String,
    pub(crate) pid: u32,
    pub(crate) name: String,
    pub(crate) path: String,
}

/// Glob and get all process file descriptors
pub(crate) fn proc_with_sockets() -> Result<Vec<ProcInfo>, LuminationError> {
    let glob_path = "/proc/*/fd/*";
    let paths = match glob(glob_path) {
        Ok(result) => result,
        Err(err) => {
            error!("[lumination] Failed to glob proc ids: {err:?}");
            return Err(LuminationError::Procs);
        }
    };

    let mut info = Vec::new();

    for path_result in paths {
        if path_result.is_err() {
            continue;
        }

        let mut path = path_result.unwrap_or_default();
        let link = match read_link(&path) {
            Ok(result) => result,
            Err(_err) => continue,
        };

        if link.to_str().is_some_and(|x| x.contains("socket")) {
            path.pop();
            path.pop();
            let pid = path
                .file_name()
                .unwrap_or_default()
                .to_str()
                .unwrap_or_default()
                .to_string();

            path.push("exe");
            let name = match read_link(&path) {
                Ok(result) => result,
                Err(_err) => PathBuf::new(),
            };

            let proc = ProcInfo {
                socket: link.to_str().unwrap_or_default().to_string(),
                pid: pid.parse::<u32>().unwrap_or_default(),
                path: name.to_str().unwrap_or_default().to_string(),
                name: name
                    .file_name()
                    .unwrap_or_default()
                    .to_str()
                    .unwrap_or_default()
                    .to_string(),
            };
            info.push(proc);
        }
    }

    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::proc_with_sockets;

    #[test]
    fn test_proc_with_sockets() {
        let results = proc_with_sockets().unwrap();
        assert!(results.len() > 2);
    }
}
