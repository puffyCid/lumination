use lumination::connections::connections;

fn main() {
    println!("Run with sudo/admin if you want to see all connections!\n");
    let conns = connections().unwrap();

    for conn in conns {
        println!(
            "State: {:?} - Remote IP: {}:{} - Local IP: {}:{} - Protocol: {:?} - Process: {} (PID:{})",
            conn.state,
            conn.remote_address,
            conn.remote_port,
            conn.local_address,
            conn.local_port,
            conn.protocol,
            conn.process_name,
            conn.pid
        );
    }
}
