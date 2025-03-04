use crate::{
    connections::{ConnectState, NetworkState, Protocol},
    error::LuminationError,
};
use log::error;
use std::{
    ffi::c_void,
    net::{Ipv4Addr, Ipv6Addr},
};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};

use super::proc::list_procs;

/// List all TCP and UDP Windows connections
pub(crate) fn list_tcp_udp() -> Result<Vec<ConnectState>, LuminationError> {
    let af_inet = 2;
    let af_inet6 = 23;

    let mut connections = list_tcp(&af_inet);
    connections.append(&mut list_tcp(&af_inet6));
    connections.append(&mut list_udp(&af_inet));
    connections.append(&mut list_udp(&af_inet6));

    let procs = list_procs()?;

    let mut conns = Vec::new();
    for proc in procs {
        for conn in &connections {
            if proc.pid != conn.pid {
                continue;
            }

            let connect = ConnectState {
                protocol: conn.protocol.clone(),
                local_address: conn.local_address.clone(),
                local_port: conn.local_port,
                remote_address: conn.remote_address.clone(),
                remote_port: conn.remote_port,
                state: conn.state.clone(),
                pid: proc.pid as u64,
                process_name: proc.name.clone(),
                //process_path: String::new(),
            };

            conns.push(connect);
        }
    }

    Ok(conns)
}

#[derive(Debug)]
pub(crate) struct NetState {
    local_address: String,
    local_port: u16,
    remote_address: String,
    remote_port: u16,
    state: NetworkState,
    protocol: Protocol,
    pid: u32,
}

/// Use the Windows API `GetExtendedTcpTable` to get list of TCP connections
fn list_tcp(af_inet: &u32) -> Vec<NetState> {
    let mut size: u32 = 0;
    let mut table: Vec<u8> = Vec::with_capacity(size as usize);
    let mut net = Vec::new();

    #[allow(unsafe_code)]
    unsafe {
        // First request will get size of the TCP table
        let mut status = GetExtendedTcpTable(
            Some(table.as_mut_ptr().cast::<c_void>()),
            &mut size,
            false,
            *af_inet,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        let buffer_too_small = 122;
        let limit = 100;
        let mut count = 0;
        // Spam the function until out `table` is the proper size
        while status == buffer_too_small {
            table = Vec::with_capacity(size as usize);
            status = GetExtendedTcpTable(
                Some(table.as_mut_ptr().cast::<c_void>()),
                &mut size,
                false,
                *af_inet,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            count += 1;
            // Should only take two calls. But just incase we set limit
            if count > limit {
                error!("[lumination] Failed to allocate buffer. Return zero connections");
                return net;
            }
        }
        count = 0;

        // Check if IPv4
        if *af_inet == 2 {
            let table2 = &*(table.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>());
            let rows = &table2.table[0] as *const MIB_TCPROW_OWNER_PID;

            while count < table2.dwNumEntries {
                let row = &*rows.add(count as usize);

                let tcp = NetState {
                    local_address: Ipv4Addr::from(u32::from_be(row.dwLocalAddr)).to_string(),
                    local_port: u16::from_be(row.dwLocalPort as u16),
                    remote_address: Ipv4Addr::from(u32::from_be(row.dwRemoteAddr)).to_string(),
                    remote_port: u16::from_be(row.dwRemotePort as u16),
                    state: get_state(&row.dwState),
                    protocol: Protocol::Tcp,
                    pid: row.dwOwningPid,
                };

                net.push(tcp);
                count += 1;
            }
        } else {
            let table2 = &*(table.as_ptr().cast::<MIB_TCP6TABLE_OWNER_PID>());
            let rows = &table2.table[0] as *const MIB_TCP6ROW_OWNER_PID;

            while count < table2.dwNumEntries {
                let row = &*rows.add(count as usize);

                let tcp = NetState {
                    local_address: Ipv6Addr::from(row.ucLocalAddr).to_string(),
                    local_port: u16::from_be(row.dwLocalPort as u16),
                    remote_address: Ipv6Addr::from(row.ucRemoteAddr).to_string(),
                    remote_port: u16::from_be(row.dwRemotePort as u16),
                    state: get_state(&row.dwState),
                    protocol: Protocol::Tcp,
                    pid: row.dwOwningPid,
                };

                net.push(tcp);
                count += 1;
            }
        }
    }

    net
}

/// Use the Windows API `GetExtendedUdpTable` to get list of UDP connections
fn list_udp(af_inet: &u32) -> Vec<NetState> {
    let mut size: u32 = 0;
    let mut table: Vec<u8> = Vec::with_capacity(size as usize);
    let mut net = Vec::new();

    #[allow(unsafe_code)]
    unsafe {
        // First request will get size of the UDP table
        let mut status = GetExtendedUdpTable(
            Some(table.as_mut_ptr().cast::<c_void>()),
            &mut size,
            false,
            *af_inet,
            UDP_TABLE_OWNER_PID,
            0,
        );
        let buffer_too_small = 122;
        let limit = 100;
        let mut count = 0;
        // Spam the function until out `table` is the proper size
        while status == buffer_too_small {
            table = Vec::with_capacity(size as usize);
            status = GetExtendedUdpTable(
                Some(table.as_mut_ptr().cast::<c_void>()),
                &mut size,
                false,
                *af_inet,
                UDP_TABLE_OWNER_PID,
                0,
            );

            count += 1;
            // Should only take two calls. But just incase we set limit
            if count > limit {
                error!("[lumination] Failed to allocate buffer. Return zero connections");
                return net;
            }
        }
        count = 0;

        // Check if IPv4
        if *af_inet == 2 {
            let table2 = &*(table.as_ptr().cast::<MIB_UDPTABLE_OWNER_PID>());
            let rows = &table2.table[0] as *const MIB_UDPROW_OWNER_PID;

            while count < table2.dwNumEntries {
                let row = &*rows.add(count as usize);

                let tcp = NetState {
                    local_address: Ipv4Addr::from(u32::from_be(row.dwLocalAddr)).to_string(),
                    local_port: u16::from_be(row.dwLocalPort as u16),
                    remote_address: String::new(),
                    remote_port: 0,
                    state: NetworkState::None,
                    protocol: Protocol::Udp,
                    pid: row.dwOwningPid,
                };

                net.push(tcp);
                count += 1;
            }
        } else {
            let table2 = &*(table.as_ptr().cast::<MIB_UDP6TABLE_OWNER_PID>());
            let rows = &table2.table[0] as *const MIB_UDP6ROW_OWNER_PID;

            while count < table2.dwNumEntries {
                let row = &*rows.add(count as usize);

                let tcp = NetState {
                    local_address: Ipv6Addr::from(row.ucLocalAddr).to_string(),
                    local_port: u16::from_be(row.dwLocalPort as u16),
                    remote_address: String::new(),
                    remote_port: 0,
                    state: NetworkState::None,
                    protocol: Protocol::Udp,
                    pid: row.dwOwningPid,
                };

                net.push(tcp);
                count += 1;
            }
        }
    }

    net
}

/// Get the network state
fn get_state(state: &u32) -> NetworkState {
    match state {
        1 => NetworkState::Close,
        2 => NetworkState::Listen,
        3 => NetworkState::SynSent,
        4 => NetworkState::SynRecv,
        5 => NetworkState::Established,
        6 => NetworkState::FinWait,
        7 => NetworkState::FinWait2,
        8 => NetworkState::CloseWait,
        9 => NetworkState::Closing,
        10 => NetworkState::LastAck,
        11 => NetworkState::TimeWait,
        12 => NetworkState::DeleteTcb,
        _ => NetworkState::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::list_tcp_udp;
    use crate::connections::NetworkState;

    #[test]
    fn test_list_tcp_udp() {
        let status = list_tcp_udp().unwrap();
        for entry in status {
            assert_ne!(entry.state, NetworkState::Unknown);
        }
    }
}
