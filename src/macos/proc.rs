use crate::error::LuminationError;
use libc::{proc_listpids, proc_name, proc_pidfdinfo, proc_pidinfo, sysctl};
use log::warn;
use nom::{
    bytes::complete::{take, take_until},
    number::complete::{be_u8, be_u16, be_u32, be_u128, le_u8, le_u32, le_u128},
};
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
pub(crate) fn list_procs() -> Result<Vec<MacosProcs>, LuminationError> {
    let mut pid_count = 0;
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
            // println!("{fd_sockets:?}");

            // Finally get socket info
            let socket_flavor = 3;
            let udp = 1;
            let tcp = 2;
            for fd in fd_sockets {
                let mut socket_info: MaybeUninit<CSocketFdInfo> = MaybeUninit::uninit();

                let struct_size =
                    c_int::try_from(mem::size_of::<CSocketFdInfo>()).unwrap_or_default();
                //println!("buff size: {struct_size}");

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
                println!("kind: {}", info.psi.soi_kind);
                println!("proto: {}", info.psi.soi_protocol);
                println!("{}", info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport);
                //panic!("stop!");
            }

            let proc = MacosProcs { pid, name };
            procs.push(proc);
        }
    }

    Ok(procs)
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

fn test_connects() {
    let mut tcp_oid = vec![4, 2, 6, 173];
    let mut udp_oid = vec![4, 2, 17, 106];
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

        let mut val: Vec<libc::c_uchar> = vec![0; val_len];
        let mut new_val_len = val_len;
        let status = sysctl(
            tcp_oid.as_mut_ptr(),
            tcp_oid.len() as u32,
            val.as_mut_ptr() as *mut libc::c_void,
            &mut new_val_len,
            std::ptr::null_mut(),
            0,
        );

        parse_binary_tcp(&val).unwrap();
    }
}

/// Parse the xtcpcb_n format
/// We just grab what we need and leave
/// This data is obtained from the kernel syscall net.inet.tcp.pcblist_n and net.inet.udp.pcblist_n
fn parse_binary_tcp(data: &[u8]) -> nom::IResult<&[u8], ()> {
    // Here be dragons...
    // References:
    // https://stackoverflow.com/questions/44474144/convert-uint8-array-to-xinpgen-struct
    // https://git.imbytecat.com/history-museum/clash/src/commit/02d9169b5d1e45a47f0f0355a32bff045838d621/rules/process_darwin.go
    // https://newosxbook.com/bonus/vol1ch16.html

    let xpingen_size: u8 = 24;
    let (mut remaining, _xpingen) = take(xpingen_size)(data)?;
    let min_size = 616;

    let tcp_length = 104;
    let tcp = 16;
    while remaining.len() > min_size {
        // println!("{remaining:?}");

        let (input, length) = le_u32(remaining)?;
        // Should always be 104 bytes
        if length != tcp_length {
            panic!("hmm");
            break;
        }

        let (input, protocol_family) = le_u32(input)?;
        // Should always be TCP since we use net.inet.tcp.pcblist_n syscall
        if protocol_family != tcp {
            panic!("what?");
            break;
        }

        let (input, _xi_inpp) = take(size_of::<u64>())(input)?;
        let (input, remote_port) = be_u16(input)?;
        let (input, local_port) = be_u16(input)?;
        let (input, _inp_ppcb) = take(size_of::<u64>())(input)?;
        let (input, _inp_gencnt) = take(size_of::<u64>())(input)?;
        let (input, _flags) = take(size_of::<u32>())(input)?;
        let (input, _flow) = take(size_of::<u32>())(input)?;
        let (input, ttl) = take(size_of::<u32>())(input)?;
        let (_, is_ipv4) = le_u8(ttl)?;
        let padding: u8 = 12;
        let (input, _padding) = take(padding)(input)?;
        let (input, remote_ip) = if is_ipv4 == 1 {
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

        let (input, src_ip) = if is_ipv4 == 1 {
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

        let jump_to_pid: u8 = if is_ipv4 == 1 { 96 } else { 72 };
        let (input, _unknown) = take(jump_to_pid)(input)?;
        let (input, pid) = le_u32(input)?;
        println!("PID: {pid}. Remote: {remote_ip}:{remote_port} - local: {src_ip}:{local_port}");

        // Skipping rest of format
        let next_section: [u8; 8] = [104, 0, 0, 0, 16, 0, 0, 0];
        let remaining_bytes: u16 = 436;
        let input = match scan_protocol(input, next_section.as_slice()) {
            Ok((result, _)) => result,
            Err(_err) => break,
        };
        remaining = input;
    }
    Ok((&[], ()))
}

fn scan_protocol<'a>(data: &'a [u8], start: &[u8]) -> nom::IResult<&'a [u8], ()> {
    let (remaining, _) = take_until(start)(data)?;
    Ok((remaining, ()))
}

#[cfg(test)]
mod tests {
    use crate::macos::proc::test_connects;

    use super::list_procs;

    #[test]
    fn test_list_procs() {
        let status = list_procs().unwrap();
        assert!(status.len() > 3);
    }

    #[test]
    fn test_test_connects() {
        let status = test_connects();
        //assert!(status.len() > 3);
    }
}
