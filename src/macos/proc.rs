use crate::{
    connections::{ConnectState, Protocol},
    error::LuminationError,
    macos::net::get_state,
};
use libc::{proc_listpids, proc_name, proc_pidfdinfo, proc_pidinfo};
use log::warn;
use std::{
    ffi::{c_char, c_int, c_longlong, c_short, c_uchar, c_uint, c_ushort, c_void},
    mem::{self, MaybeUninit},
    net::{Ipv4Addr, Ipv6Addr},
    ptr,
};

#[derive(Debug)]
pub(crate) struct MacosProcs {
    pub(crate) pid: i32,
    pub(crate) name: String,
}

#[repr(C)]
#[derive(Debug, Default)]
struct FdInfo {
    proc_fd: i32,
    proc_fd_type: u32,
}

// From https://github.com/GyulyVGC/listeners/blob/215d93cf774bc0e1e071457983e13a88f1350ba4/src/platform/macos/c_socket_fd_info.rs#L9
#[repr(C)]
struct CSocketFdInfo {
    pfi: ProcFileinfo,
    psi: SocketInfo,
}

/// Get process listing and network connections using file descriptors
pub(crate) fn list_procs(conns: &mut Vec<ConnectState>) -> Result<(), LuminationError> {
    let pid_count;
    let all_pids = 1;
    let typeinfo = 0;
    let buff_size = 0;
    let mut procs = Vec::new();

    #[allow(unsafe_code)]
    unsafe {
        // Need to call twice in order to get proper size
        pid_count = proc_listpids(all_pids, typeinfo, ptr::null_mut(), buff_size);

        if pid_count <= 0 {
            warn!("[lumination] Could not determine pid count. Got {pid_count}");
            return Err(LuminationError::Procs);
        }

        let mut pids: Vec<c_int> = Vec::new();
        pids.resize(
            usize::try_from(pid_count).unwrap_or_default(),
            Default::default(),
        );

        let _status = proc_listpids(
            all_pids,
            typeinfo,
            pids.as_mut_ptr().cast::<c_void>(),
            c_int::try_from(pids.len() * mem::size_of::<c_int>()).unwrap_or_default(),
        );
        pids = pids.into_iter().filter(|f| *f > 0).collect::<Vec<i32>>();

        let max_size = 4096;

        for pid in pids {
            let mut buf = vec![0; max_size];
            let buff_ptr = buf.as_mut_ptr().cast::<c_void>();
            let buff_size = u32::try_from(buf.capacity()).unwrap_or_default();

            let status = proc_name(pid, buff_ptr, buff_size);
            if status <= 0 {
                continue;
            }

            buf.set_len(usize::try_from(status).unwrap_or_default());
            let name = String::from_utf8(buf).unwrap_or_default();

            let fd_info = 1;
            // Need to call twice
            let fd_buff_size = proc_pidinfo(pid, fd_info, 0, ptr::null_mut(), 0);
            if fd_buff_size <= 0 {
                warn!("[lumination] Could not determine file descriptor info. Got {fd_buff_size}");
                continue;
            }
            let fd_size = 8;
            let fd_count = usize::try_from(fd_buff_size).unwrap_or_default() / fd_size;
            let mut fds_buff: Vec<FdInfo> = Vec::new();
            fds_buff.resize_with(fd_count, FdInfo::default);
            let status = proc_pidinfo(
                pid,
                fd_info,
                0,
                fds_buff.as_mut_ptr().cast::<c_void>(),
                fd_buff_size,
            );
            if status <= 0 {
                continue;
            }

            let socket = 2;
            let mut fd_sockets = Vec::new();
            for entry in fds_buff {
                if entry.proc_fd_type != socket {
                    continue;
                }
                fd_sockets.push(entry);
            }
            if fd_sockets.is_empty() {
                continue;
            }

            // Finally get socket info
            let socket_flavor = 3;
            let udp = 1;
            let tcp = 2;

            for fd in fd_sockets {
                let mut socket_info: MaybeUninit<CSocketFdInfo> = MaybeUninit::uninit();

                let struct_size =
                    c_int::try_from(mem::size_of::<CSocketFdInfo>()).unwrap_or_default();

                let status = proc_pidfdinfo(
                    pid,
                    fd.proc_fd,
                    socket_flavor,
                    socket_info.as_mut_ptr().cast::<c_void>(),
                    struct_size,
                );
                if status < 0 {
                    continue;
                }

                let info = socket_info.assume_init();
                if info.psi.soi_kind != tcp && info.psi.soi_kind != udp {
                    continue;
                }

                let mut conn = ConnectState {
                    protocol: get_protocol(&info.psi.soi_protocol),
                    local_address: String::new(),
                    local_port: 0,
                    remote_address: String::new(),
                    remote_port: 0,
                    state: get_state(&(info.psi.soi_proto.pri_tcp.tcpsi_state as u32)),
                    pid: pid as u32,
                    process_name: name.clone(),
                };
                get_ips(
                    info.psi.soi_family,
                    info.psi.soi_proto.pri_tcp.tcpsi_ini,
                    &mut conn,
                );
                conns.push(conn);
            }

            let proc = MacosProcs { pid, name };
            procs.push(proc);
        }
    }

    // Go through Process info and update our other network connections from `list_connections`
    for conn in conns {
        if !conn.process_name.is_empty() {
            continue;
        }
        for proc in &procs {
            if conn.pid as i32 != proc.pid {
                continue;
            }

            conn.process_name = proc.name.clone();
        }
    }

    Ok(())
}

fn get_ips(family: i32, sock_addr: InSockinfo, conn: &mut ConnectState) {
    let ipv4 = 2;
    let ipv6 = 30;
    if family == ipv4 {
        #[allow(unsafe_code)]
        unsafe {
            let remote_ip = sock_addr.insi_faddr.ina_46.i46a_addr4.s_addr;
            let ip4 = Ipv4Addr::from_bits(u32::from_be(remote_ip));
            conn.remote_address = ip4.to_string();

            if sock_addr.insi_fport >= 0 {
                conn.remote_port = sock_addr.insi_fport as u16;
            }

            let local_ip = sock_addr.insi_laddr.ina_46.i46a_addr4.s_addr;
            let ip4 = Ipv4Addr::from_bits(u32::from_be(local_ip));
            conn.local_address = ip4.to_string();

            if sock_addr.insi_lport >= 0 {
                conn.local_port = sock_addr.insi_fport as u16;
            }
        }
    } else if family == ipv6 {
        #[allow(unsafe_code)]
        unsafe {
            let remote_ip = sock_addr.insi_faddr.ina_6.__u6_addr.__u6_addr8;
            if remote_ip.len() < 16 {
                return;
            }
            let ip6 = Ipv6Addr::from_bits(u128::from_be_bytes(remote_ip));
            conn.remote_address = ip6.to_string();

            if sock_addr.insi_fport >= 0 {
                conn.remote_port = sock_addr.insi_fport as u16;
            }

            let local_ip = sock_addr.insi_laddr.ina_6.__u6_addr.__u6_addr8;
            if local_ip.len() < 16 {
                return;
            }
            let ip6 = Ipv6Addr::from_bits(u128::from_be_bytes(local_ip));
            conn.local_address = ip6.to_string();

            if sock_addr.insi_lport >= 0 {
                conn.local_port = sock_addr.insi_fport as u16;
            }
        }
    }
}

fn get_protocol(proto: &i32) -> Protocol {
    match proto {
        6 => Protocol::Tcp,
        17 => Protocol::Udp,
        1 => Protocol::Icmp,
        _ => Protocol::Unknown,
    }
}

#[repr(C)]
struct ProcFileinfo {
    fi_openflags: u32,
    fi_status: u32,
    fi_offset: c_longlong,
    fi_type: i32,
    fi_guardflags: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct SocketInfo {
    soi_stat: VinfoStat,
    soi_so: u64,
    soi_pcb: u64,
    soi_type: c_int,
    soi_protocol: c_int,
    soi_family: c_int,
    soi_options: c_short,
    soi_linger: c_short,
    soi_state: c_short,
    soi_qlen: c_short,
    soi_incqlen: c_short,
    soi_qlimit: c_short,
    soi_timeo: c_short,
    soi_error: c_ushort,
    soi_oobmark: u32,
    soi_rcv: SockbufInfo,
    soi_snd: SockbufInfo,
    soi_kind: c_int,
    rfu_1: u32,
    soi_proto: SocketInfoBindgenTy1,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct VinfoStat {
    vst_dev: u32,
    vst_mode: u16,
    vst_nlink: u16,
    vst_ino: u64,
    vst_uid: c_uint,
    vst_gid: c_uint,
    vst_atime: i64,
    vst_atimensec: i64,
    vst_mtime: i64,
    vst_mtimensec: i64,
    vst_ctime: i64,
    vst_ctimensec: i64,
    vst_birthtime: i64,
    vst_birthtimensec: i64,
    vst_size: c_longlong,
    vst_blocks: i64,
    vst_blksize: i32,
    vst_flags: u32,
    vst_gen: u32,
    vst_rdev: u32,
    vst_qspare: [i64; 2usize],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct SockbufInfo {
    sbi_cc: u32,
    sbi_hiwat: u32,
    sbi_mbcnt: u32,
    sbi_mbmax: u32,
    sbi_lowat: u32,
    sbi_flags: c_short,
    sbi_timeo: c_short,
}

#[repr(C)]
#[derive(Copy, Clone)]
union SocketInfoBindgenTy1 {
    pri_in: InSockinfo,
    pri_tcp: TcpSockinfo,
    pri_un: UnSockinfo,
    pri_ndrv: NdrvInfo,
    pri_kern_event: KernEventInfo,
    pri_kern_ctl: KernCtlInfo,
    _bindgen_union_align: [u64; 66usize],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct InSockinfo {
    insi_fport: c_int,
    insi_lport: c_int,
    insi_gencnt: u64,
    insi_flags: u32,
    insi_flow: u32,
    insi_vflag: u8,
    insi_ip_ttl: u8,
    rfu_1: u32,
    insi_faddr: InSockinfoBindgenTy1,
    insi_laddr: InSockinfoBindgenTy2,
    insi_v4: InSockinfoBindgenTy3,
    insi_v6: InSockinfoBindgenTy4,
}

#[repr(C)]
#[derive(Copy, Clone)]
union InSockinfoBindgenTy1 {
    ina_46: In4in6Addr,
    ina_6: In6Addr,
    _bindgen_union_align: [u32; 4usize],
}

#[repr(C)]
#[derive(Copy, Clone)]
union InSockinfoBindgenTy2 {
    ina_46: In4in6Addr,
    ina_6: In6Addr,
    _bindgen_union_align: [u32; 4usize],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct InSockinfoBindgenTy3 {
    in4_tos: c_uchar,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct InSockinfoBindgenTy4 {
    in6_hlim: u8,
    in6_cksum: c_int,
    in6_ifindex: c_ushort,
    in6_hops: c_short,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct In4in6Addr {
    i46a_pad32: [c_uint; 3usize],
    i46a_addr4: InAddr,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct InAddr {
    s_addr: c_uint,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct In6Addr {
    __u6_addr: In6AddrBindgenTy1,
}

#[repr(C)]
#[derive(Copy, Clone)]
union In6AddrBindgenTy1 {
    __u6_addr8: [c_uchar; 16usize],
    __u6_addr16: [c_ushort; 8usize],
    __u6_addr32: [c_uint; 4usize],
    _bindgen_union_align: [u32; 4usize],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct TcpSockinfo {
    tcpsi_ini: InSockinfo,
    tcpsi_state: c_int,
    tcpsi_timer: [c_int; 4usize],
    tcpsi_mss: c_int,
    tcpsi_flags: u32,
    rfu_1: u32,
    tcpsi_tp: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct UnSockinfo {
    unsi_conn_so: u64,
    unsi_conn_pcb: u64,
    unsi_addr: UnSockinfoBindgenTy1,
    unsi_caddr: UnSockinfoBindgenTy2,
}

#[repr(C)]
#[derive(Copy, Clone)]
union UnSockinfoBindgenTy1 {
    ua_sun: SockaddrUn,
    ua_dummy: [c_char; 255usize],
    _bindgen_union_align: [u8; 255usize],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct SockaddrUn {
    sun_len: c_uchar,
    sun_family: c_uchar,
    sun_path: [c_char; 104usize],
}

#[repr(C)]
#[derive(Copy, Clone)]
union UnSockinfoBindgenTy2 {
    ua_sun: SockaddrUn,
    ua_dummy: [c_char; 255usize],
    _bindgen_union_align: [u8; 255usize],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct NdrvInfo {
    ndrvsi_if_family: u32,
    ndrvsi_if_unit: u32,
    ndrvsi_if_name: [c_char; 16usize],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct KernEventInfo {
    kesi_vendor_code_filter: u32,
    kesi_class_filter: u32,
    kesi_subclass_filter: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct KernCtlInfo {
    kcsi_id: u32,
    kcsi_reg_unit: u32,
    kcsi_flags: u32,
    kcsi_recvbufsize: u32,
    kcsi_sendbufsize: u32,
    kcsi_unit: u32,
    kcsi_name: [c_char; 96usize],
}

#[cfg(test)]
mod tests {
    use super::list_procs;

    #[test]
    fn test_list_procs() {
        let mut conns = Vec::new();
        list_procs(&mut conns).unwrap();
        assert!(conns.len() > 3);
    }
}
