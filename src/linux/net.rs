use super::proc::proc_with_sockets;
use crate::{
    connections::{ConnectState, NetworkState, Protocol},
    error::LuminationError,
};
use log::error;
use nom::{
    bytes::complete::{is_a, take, take_until},
    error::ErrorKind,
};
use std::{
    fs::File,
    io::{BufRead, BufReader},
    net::{Ipv4Addr, Ipv6Addr},
};

/// List TCP, UDP, and ICMP connections
pub(crate) fn list_tcp_udp() -> Result<Vec<ConnectState>, LuminationError> {
    let paths = vec![
        "/proc/net/tcp",
        "/proc/net/udp",
        "/proc/net/icmp",
        "/proc/net/tcp6",
        "/proc/net/udp6",
    ];

    let mut connections = Vec::new();
    for path in paths {
        let mut status = match read_net(path) {
            Ok((_, result)) => result,
            Err(err) => {
                error!("[lumination] Could not parse {path}: {err:?}");
                return Err(LuminationError::Net);
            }
        };

        connections.append(&mut status);
    }

    let procs = proc_with_sockets()?;

    let mut conns = Vec::new();
    for proc in procs {
        for conn in &connections {
            if proc.socket.contains(&format!("socket:[{}]", conn.inode)) {
                let connect = ConnectState {
                    protocol: conn.protocol.clone(),
                    local_address: conn.local_address.clone(),
                    local_port: conn.local_port,
                    remote_address: conn.remote_address.clone(),
                    remote_port: conn.remote_port,
                    state: conn.state.clone(),
                    pid: proc.pid,
                    process_name: proc.name.clone(),
                    process_path: proc.path.clone(),
                };
                conns.push(connect);
            }
        }
    }

    Ok(conns)
}

/// Read each line associated with TCP, UDP, or ICMP file
fn read_net(path: &str) -> nom::IResult<&str, Vec<NetState>> {
    let file = match File::open(path) {
        Ok(result) => result,
        Err(err) => {
            error!("[lumination] Failed to open {path}: {err:?}");
            return Err(nom::Err::Failure(nom::error::Error::new(
                "",
                ErrorKind::Fail,
            )));
        }
    };

    let protocol = if path.contains("tcp") {
        Protocol::Tcp
    } else if path.contains("udp") {
        Protocol::Udp
    } else if path.contains("icmp") {
        Protocol::Icmp
    } else {
        Protocol::Unknown
    };

    let buf_reader = BufReader::new(file);
    let lines = buf_reader.lines();

    let mut entries = Vec::new();
    for entry in lines {
        if entry.is_err() {
            continue;
        }
        let value = entry.unwrap_or_default();
        // Skip first line
        if value.contains("local_address") {
            continue;
        }

        let (_, status) = parse_net(&value, &protocol).unwrap();
        entries.push(status);
    }

    Ok((path, entries))
}

#[derive(Debug)]
pub(crate) struct NetState {
    local_address: String,
    local_port: u32,
    remote_address: String,
    remote_port: u32,
    state: NetworkState,
    inode: u64,
    _uid: u64,
    protocol: Protocol,
}

/// Parse the connection line with nom
fn parse_net<'a>(line: &'a str, protocol: &Protocol) -> nom::IResult<&'a str, NetState> {
    let mut input = line;
    if line.starts_with(" ") {
        let (remaining, _whitespace) = is_a(" ")(input)?;
        input = remaining;
    }
    let (input, _entry) = take_until(":")(input)?;
    let (input, _) = take(2u8)(input)?;
    let (input, local_hex) = take_until(":")(input)?;
    let (input, _) = take(1u8)(input)?;
    let (input, local_port) = take_until(" ")(input)?;

    let (input, _) = take(1u8)(input)?;
    let (input, remote_hex) = take_until(":")(input)?;
    let (input, _) = take(1u8)(input)?;
    let (input, remote_port) = take_until(" ")(input)?;
    let (input, _) = take(1u8)(input)?;

    let (input, state_value) = take_until(" ")(input)?;
    // nom until we get to UID field
    let (input, _) = take(1u8)(input)?;
    let (input, _) = take_until(" ")(input)?;
    let (input, _) = take(1u8)(input)?;
    let (input, _) = take_until(" ")(input)?;
    let (input, _) = take(1u8)(input)?;
    let (input, _) = take_until(" ")(input)?;
    let (input, _whitespace) = is_a(" ")(input)?;

    let (input, uid) = take_until(" ")(input)?;
    let (input, _whitespace) = is_a(" ")(input)?;
    let (input, _) = take_until(" ")(input)?;
    let (input, _) = take(1u8)(input)?;

    let (input, inode) = take_until(" ")(input)?;

    let mut local_address: String = local_hex.to_string();
    let ipv6 = 32;
    if local_address.len() == ipv6 {
        if let Ok(ip_dec) = u128::from_str_radix(&local_address, 16) {
            let ip = Ipv6Addr::from(u128::from_be(ip_dec));
            local_address = ip.to_string();
        }
    } else if let Ok(ip_dec) = u32::from_str_radix(&local_address, 16) {
        let ip = Ipv4Addr::from(u32::from_be(ip_dec));
        local_address = ip.to_string();
    }

    let mut remote_address: String = remote_hex.to_string();
    if remote_address.len() == ipv6 {
        if let Ok(ip_dec) = u128::from_str_radix(&remote_address, 16) {
            let ip = Ipv6Addr::from(u128::from_be(ip_dec));
            remote_address = ip.to_string();
        }
    } else if let Ok(ip_dec) = u32::from_str_radix(&remote_address, 16) {
        let ip = Ipv4Addr::from(u32::from_be(ip_dec));
        remote_address = ip.to_string();
    }

    let tcp_state = NetState {
        local_address,
        local_port: u32::from_str_radix(local_port, 16).unwrap_or_default(),
        remote_address,
        remote_port: u32::from_str_radix(remote_port, 16).unwrap_or_default(),
        state: get_state(state_value),
        inode: inode.parse::<u64>().unwrap_or_default(),
        _uid: uid.parse::<u64>().unwrap_or_default(),
        protocol: protocol.clone(),
    };

    Ok((input, tcp_state))
}

/// Get the network state
fn get_state(state: &str) -> NetworkState {
    match state {
        "01" => NetworkState::Established,
        "02" => NetworkState::SynSent,
        "03" => NetworkState::SynRecv,
        "04" => NetworkState::FinWait,
        "05" => NetworkState::FinWait2,
        "06" => NetworkState::TimeWait,
        "07" => NetworkState::Close,
        "08" => NetworkState::CloseWait,
        "09" => NetworkState::LastAck,
        "0A" => NetworkState::Listen,
        "0B" => NetworkState::Closing,
        _ => NetworkState::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::{get_state, list_tcp_udp};
    use crate::connections::NetworkState;

    #[test]
    fn test_list_tcp_udp() {
        let status = list_tcp_udp().unwrap();
        assert!(status.len() > 2);
    }

    #[test]
    fn test_get_state() {
        let test = [
            "01", "02", "03", "04", "05", "06", "07", "08", "09", "0A", "0B",
        ];

        for entry in test {
            let state = get_state(&entry);
            assert_ne!(state, NetworkState::Unknown);
        }
    }
}
