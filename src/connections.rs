use crate::error::LuminationError;

#[derive(Debug, Clone)]
pub struct ConnectState {
    pub protocol: Protocol,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub state: NetworkState,
    pub pid: u64,
    pub process_name: String,
    //pub process_path: String,
}

#[derive(Debug, PartialEq, Clone)]
pub enum NetworkState {
    Listen,
    Established,
    SynRecv,
    SynSent,
    FinWait,
    FinWait2,
    TimeWait,
    Close,
    CloseWait,
    LastAck,
    Closing,
    DeleteTcb,
    Unknown,
    None,
}

#[derive(Debug, Clone)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Unknown,
}

/// List current network connections on a system
pub fn connections() -> Result<Vec<ConnectState>, LuminationError> {
    let connects;

    #[cfg(target_os = "linux")]
    {
        use crate::linux::net::list_tcp_udp;

        connects = list_tcp_udp()?;
    }
    #[cfg(target_os = "windows")]
    {
        use crate::windows::net::list_tcp_udp;

        connects = list_tcp_udp()?;
    }

    Ok(connects)
}

#[cfg(test)]
mod tests {
    use super::connections;

    #[test]
    fn test_connections() {
        let conn = connections().unwrap();
        assert!(conn.len() > 2);
    }
}
