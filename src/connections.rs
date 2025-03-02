use crate::{error::LuminationError, linux::net::list_tcp_udp};

#[derive(Debug, Clone)]
pub struct ConnectState {
    pub protocol: Protocol,
    pub local_address: String,
    pub local_port: u32,
    pub remote_address: String,
    pub remote_port: u32,
    pub state: NetworkState,
    pub pid: u64,
    pub process_name: String,
    pub process_path: String,
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
    Unknown,
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
    println!("hmm where to start??");
    let mut connects = Vec::new();

    if cfg!(target_os = "linux") {
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
