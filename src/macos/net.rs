use super::proc::list_procs;
use crate::{
    connections::{ConnectState, NetworkState, Protocol},
    error::LuminationError,
};
use libc::sysctl;
use log::error;
use nom::{
    bytes::complete::take,
    number::complete::{be_u16, be_u32, be_u128, le_u8, le_u32},
};
use std::net::{Ipv4Addr, Ipv6Addr};

pub(crate) fn list_tcp_udp() -> Result<Vec<ConnectState>, LuminationError> {
    // First get connections using sysctl. Which is is a kernel call
    // Contains socket connections but no process name
    let mut conns = list_connections();

    // Now get process listing and additional connections. There is a small "race condition" when mapping connections to processes
    // If the process ends before we get the process listing we will not be able to get the process name
    // There is also a chance that the PID could be reused
    list_procs(&mut conns)?;

    Ok(conns)
}

/// Get TCP and UDP connections by using `sysctl`
fn list_connections() -> Vec<ConnectState> {
    let mut tcp_oid = vec![4, 2, 6, 173];
    let mut udp_oid = vec![4, 2, 17, 106];
    let mut conns = Vec::new();
    #[allow(unsafe_code)]
    unsafe {
        let mut val_len = 0;
        let status = sysctl(
            tcp_oid.as_mut_ptr(),
            tcp_oid.len() as u32,
            std::ptr::null_mut(),
            &mut val_len,
            std::ptr::null_mut(),
            0,
        );

        if status != 0 {
            error!(
                "[lumination] Failed to get tcp socket data size. Wanted status 0, got {status}"
            );
            return conns;
        }

        let mut val: Vec<libc::c_uchar> = vec![0; val_len];
        let mut new_val_len = val_len;
        let status = sysctl(
            tcp_oid.as_mut_ptr(),
            tcp_oid.len() as u32,
            val.as_mut_ptr().cast::<libc::c_void>(),
            &mut new_val_len,
            std::ptr::null_mut(),
            0,
        );
        if status != 0 {
            error!("[lumination] Failed to get tcp socket data. Wanted status 0, got {status}");
            return conns;
        }

        let tcp_conns = match parse_socket_options(&val, &Protocol::Tcp) {
            Ok((_, results)) => results,
            Err(err) => {
                error!("[lumination] Failed to parse tcp socket data: {err:?}");
                return conns;
            }
        };
        conns = tcp_conns;

        let mut val_len = 0;
        let status = sysctl(
            udp_oid.as_mut_ptr(),
            udp_oid.len() as u32,
            std::ptr::null_mut(),
            &mut val_len,
            std::ptr::null_mut(),
            0,
        );

        if status != 0 {
            error!(
                "[lumination] Failed to get udp socket data size. Wanted status 0, got {status}"
            );
            return conns;
        }

        let mut val: Vec<libc::c_uchar> = vec![0; val_len];
        let mut new_val_len = val_len;
        let status = sysctl(
            udp_oid.as_mut_ptr(),
            udp_oid.len() as u32,
            val.as_mut_ptr().cast::<libc::c_void>(),
            &mut new_val_len,
            std::ptr::null_mut(),
            0,
        );

        if status != 0 {
            error!("[lumination] Failed to get udp socket data. Wanted status 0, got {status}");
            return conns;
        }

        let mut udp_conns = match parse_socket_options(&val, &Protocol::Udp) {
            Ok((_, results)) => results,
            Err(err) => {
                error!("[lumination] Failed to parse udp socket data: {err:?}");
                return conns;
            }
        };
        conns.append(&mut udp_conns);
    }
    conns
}

/// Parse the socket format
/// We just grab what we need and leave
/// This data is obtained from the kernel syscall `net.inet.tcp.pcblist_n` and `net.inet.udp.pcblist_n`
/// This is what netstat does
fn parse_socket_options<'a>(
    data: &'a [u8],
    protocol: &Protocol,
) -> nom::IResult<&'a [u8], Vec<ConnectState>> {
    // Here be dragons...
    // Format: https://github.com/xamarin/web-tests/blob/master/NetworkTools/Apple/netstat.h

    let xpingen_size: u8 = 24;
    if data.len() < xpingen_size as usize {
        return Ok((&[], Vec::new()))
    }
    // Skip header info. We do not need it
    let (mut remaining, _xpingen) = take(xpingen_size)(data)?;
    let min_size = 616;

    let inpcb = 16;
    let tcpcb = 32;
    let socket = 1;
    let rcvbuf = 2;
    let sndbuf = 4;
    let stats = 8;
    let mut conn = ConnectState {
        protocol: protocol.clone(),
        local_address: String::new(),
        local_port: 0,
        remote_address: String::new(),
        remote_port: 0,
        state: NetworkState::Unknown,
        pid: 0,
        process_name: String::new(),
    };

    let mut conns = Vec::new();
    // Parse socket data
    while remaining.len() > min_size {
        let (input, length) = le_u32(remaining)?;
        let adjust = 4;
        if length <= adjust || length as usize > input.len() {
            // We are done
            break;
        }

        // Length includes itself. We already nom'd that
        let (data, xso_data) = take(length - adjust)(input)?;
        remaining = data;
        let (input, xso_type) = le_u32(xso_data)?;

        /*
         * There are six types:
         * socket (1), rcvbuf (2), sndbuf (4), stats (8), inpcb (16), tcpcb (32)
         * We only care about inpcb, tcpcb, and socket
         */
        if xso_type == inpcb {
            parse_inpcb(input, &mut conn)?;
        } else if xso_type == socket {
            parse_socket(input, &mut conn)?;
            // UDP does not have a state on macOS
            if protocol == &Protocol::Udp {
                conns.push(conn.clone());
                // reset our struct
                conn = ConnectState {
                    protocol: protocol.clone(),
                    local_address: String::new(),
                    local_port: 0,
                    remote_address: String::new(),
                    remote_port: 0,
                    state: NetworkState::Unknown,
                    pid: 0,
                    process_name: String::new(),
                };
            }
        } else if xso_type == tcpcb {
            // The final structure we care about
            parse_tcpbp(input, &mut conn)?;
            conns.push(conn.clone());
            // reset our struct
            conn = ConnectState {
                protocol: protocol.clone(),
                local_address: String::new(),
                local_port: 0,
                remote_address: String::new(),
                remote_port: 0,
                state: NetworkState::Unknown,
                pid: 0,
                process_name: String::new(),
            };

            // TCP type has 4 bytes padding
            let (input, _padding) = take(size_of::<u32>())(remaining)?;
            remaining = input;
        } else if xso_type != sndbuf && xso_type != rcvbuf && xso_type != stats {
            break;
        }
    }
    Ok((&[], conns))
}

/// Get local and remote address and ports
fn parse_inpcb<'a>(data: &'a [u8], conn: &mut ConnectState) -> nom::IResult<&'a [u8], ()> {
    let (input, _xi_inpp) = take(size_of::<u64>())(data)?;
    let (input, remote_port) = be_u16(input)?;
    let (input, local_port) = be_u16(input)?;
    let (input, _inp_ppcb) = take(size_of::<u64>())(input)?;
    let (input, _inp_gencnt) = take(size_of::<u64>())(input)?;
    let (input, _flags) = take(size_of::<u32>())(input)?;
    let (input, _flow) = take(size_of::<u32>())(input)?;
    let (input, is_ipv4) = le_u8(input)?;
    let (input, _ttl) = le_u8(input)?;
    let (input, _padding) = le_u8(input)?;
    let (input, _protocol) = le_u8(input)?;

    let padding: u8 = 12;
    let (input, _padding) = take(padding)(input)?;

    let (input, remote_address) = if is_ipv4 == 1 {
        let (input, remote_ip) = be_u32(input)?;
        let ip = Ipv4Addr::from_bits(remote_ip).to_string();
        let (input, _padding) = take(padding)(input)?;

        (input, ip)
    } else {
        let ip6_padding: u8 = 4;
        let (input, _padding) = take(ip6_padding)(input)?;

        let (input, remote_ip) = be_u128(input)?;
        let ip = Ipv6Addr::from_bits(remote_ip).to_string();

        (input, ip)
    };

    let (_input, local_address) = if is_ipv4 == 1 {
        let (input, src_ip) = be_u32(input)?;
        let ip = Ipv4Addr::from_bits(src_ip).to_string();
        (input, ip)
    } else {
        let ip6_padding: u8 = 4;
        let (input, _padding) = take(ip6_padding)(input)?;

        let (input, src_ip) = be_u128(input)?;
        let ip = Ipv6Addr::from_bits(src_ip).to_string();
        (input, ip)
    };
    // Do not care about rest of the format

    conn.local_address = local_address;
    conn.remote_address = remote_address;
    conn.local_port = local_port;
    conn.remote_port = remote_port;

    Ok((&[], ()))
}

/// Parse socket info. We get the PID only
fn parse_socket<'a>(data: &'a [u8], conn: &mut ConnectState) -> nom::IResult<&'a [u8], ()> {
    let (input, _xso_so) = take(size_of::<u64>())(data)?;
    // https://github.com/xamarin/web-tests/blob/master/NetworkTools/Apple/netstat.h#L251
    // Mentions this is two bytes. But it appears to be four now?
    let (input, _so_type) = take(size_of::<u32>())(input)?;
    let (input, _so_options) = take(size_of::<u32>())(input)?;
    let (input, _linger) = take(size_of::<u16>())(input)?;

    // Not connection state
    let (input, _state) = take(size_of::<u16>())(input)?;

    let (input, _pcb) = take(size_of::<u64>())(input)?;
    let (input, _protocol) = take(size_of::<u32>())(input)?;
    let (input, _family) = take(size_of::<u32>())(input)?;
    let (input, _qlen) = take(size_of::<u16>())(input)?;
    let (input, _incqlen) = take(size_of::<u16>())(input)?;
    let (input, _qlimit) = take(size_of::<u16>())(input)?;
    let (input, _timeo) = take(size_of::<u16>())(input)?;
    let (input, _error) = take(size_of::<u16>())(input)?;

    let padding_size: u8 = 14;
    let (input, _padding) = take(padding_size)(input)?;
    let (input, pid) = le_u32(input)?;
    conn.pid = pid;

    let (input, _oobmark) = take(size_of::<u32>())(input)?;
    let (_input, _uid) = take(size_of::<u32>())(input)?;

    Ok((&[], ()))
}

/// Parse connection state. Lots of info here. But we only care about the network state
fn parse_tcpbp<'a>(data: &'a [u8], conn: &mut ConnectState) -> nom::IResult<&'a [u8], ()> {
    let (input, _segq) = take(size_of::<u64>())(data)?;
    let (input, _dupacks) = take(size_of::<u32>())(input)?;

    let timer_size: u8 = 16;
    let (input, _timers) = take(timer_size)(input)?;
    let (_input, state) = le_u32(input)?;
    conn.state = get_state(&state);

    Ok((&[], ()))
}

/// Determine connection state
pub(crate) fn get_state(state: &u32) -> NetworkState {
    match state {
        0 => NetworkState::Close,
        1 => NetworkState::Listen,
        2 => NetworkState::SynSent,
        3 => NetworkState::SynRecv,
        4 => NetworkState::Established,
        5 => NetworkState::CloseWait,
        6 => NetworkState::FinWait,
        7 => NetworkState::Closing,
        8 => NetworkState::LastAck,
        9 => NetworkState::FinWait2,
        10 => NetworkState::TimeWait,
        _ => NetworkState::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        connections::{ConnectState, NetworkState, Protocol},
        macos::net::{list_connections, list_tcp_udp, parse_inpcb, parse_socket, parse_tcpbp},
    };

    #[test]
    fn test_list_connections() {
        let status = list_connections();
        assert!(status.len() > 3);
    }

    #[test]
    fn test_list_tcp_udp() {
        let status = list_tcp_udp().unwrap();
        assert!(status.len() > 3);
    }

    #[test]
    fn test_parse_socket() {
        let mut conn = ConnectState {
            protocol: Protocol::Unknown,
            local_address: String::new(),
            local_port: 0,
            remote_address: String::new(),
            remote_port: 0,
            state: NetworkState::Unknown,
            pid: 0,
            process_name: String::new(),
        };

        let test = [
            58, 122, 159, 24, 13, 235, 222, 183, 1, 0, 0, 0, 8, 0, 0, 0, 0, 0, 2, 1, 237, 47, 58,
            223, 62, 23, 108, 159, 6, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 245, 1, 0, 0, 11, 88, 1, 0, 0, 0, 0, 0, 212, 117, 11, 0, 0, 0, 0,
            0, 129, 0, 0, 0, 0, 9, 0, 4, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        parse_socket(&test, &mut conn).unwrap();
        assert_eq!(conn.pid, 88075);
    }

    #[test]
    fn test_parse_tcpbp() {
        let test = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 217, 176, 0, 0, 0, 0, 0, 0,
            4, 0, 0, 0, 228, 3, 0, 84, 0, 0, 0, 0, 168, 115, 12, 16, 168, 115, 12, 16, 168, 115,
            12, 16, 168, 115, 12, 16, 244, 192, 91, 87, 168, 115, 12, 16, 12, 99, 12, 16, 158, 219,
            90, 87, 26, 193, 91, 87, 119, 186, 93, 87, 0, 0, 2, 0, 26, 193, 91, 87, 0, 152, 0, 0,
            43, 73, 0, 0, 0, 192, 255, 63, 180, 5, 0, 0, 29, 99, 226, 11, 45, 98, 226, 11, 0, 0, 0,
            0, 251, 111, 12, 16, 12, 1, 0, 0, 168, 5, 0, 0, 114, 4, 0, 0, 133, 0, 0, 0, 0, 0, 0, 0,
            30, 0, 0, 0, 5, 0, 0, 0, 0, 152, 0, 0, 0, 0, 0, 0, 0, 0, 9, 6, 6, 9, 0, 0, 104, 2, 233,
            76, 29, 99, 226, 11, 26, 193, 91, 87, 0, 0, 0, 0, 0, 0, 0, 0, 168, 115, 12, 16, 0, 0,
            0, 0, 0, 192, 255, 63,
        ];

        let mut conn = ConnectState {
            protocol: Protocol::Unknown,
            local_address: String::new(),
            local_port: 0,
            remote_address: String::new(),
            remote_port: 0,
            state: NetworkState::Unknown,
            pid: 0,
            process_name: String::new(),
        };

        parse_tcpbp(&test, &mut conn).unwrap();
        assert_eq!(conn.state, NetworkState::Established);
    }

    #[test]
    fn test_parse_inpcb() {
        let test = [
            108, 251, 232, 180, 25, 4, 226, 130, 1, 187, 194, 143, 130, 20, 83, 17, 187, 161, 30,
            74, 228, 11, 0, 0, 0, 0, 0, 0, 64, 8, 128, 0, 0, 0, 0, 0, 1, 64, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 140, 82, 114, 26, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1,
            208, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 181, 122, 46, 131, 22, 0, 0, 0,
        ];

        let mut conn = ConnectState {
            protocol: Protocol::Unknown,
            local_address: String::new(),
            local_port: 0,
            remote_address: String::new(),
            remote_port: 0,
            state: NetworkState::Unknown,
            pid: 0,
            process_name: String::new(),
        };

        parse_inpcb(&test, &mut conn).unwrap();
        assert_eq!(conn.local_address, "192.168.1.208");
        assert_eq!(conn.local_port, 49807);
        assert_eq!(conn.remote_address, "140.82.114.26");
        assert_eq!(conn.remote_port, 443);
    }
}
