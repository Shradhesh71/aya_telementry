use aya::programs::TracePoint;
use aya::maps::RingBuf;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;
use std::time::Duration;
use aya_telementry_common::Event;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/aya-telementry"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let program: &mut TracePoint = ebpf.program_mut("aya_telementry").unwrap().try_into()?;
    program.load()?;
    program.attach("net", "netif_receive_skb")?;
    // program.attach("syscalls", "sys_enter_execve")?;

    let mut ringbuf = RingBuf::try_from(ebpf.take_map("EVENTS").unwrap())?;

    println!("Listening for events...");
    println!("Watching for QUIC packets on ports 443, 4433, 8000...\n");

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                println!("Ctrl-C received, exiting...");
                break;
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                while let Some(item) = ringbuf.next() {
                    let bytes = item.as_ref();
                    if bytes.len() >= std::mem::size_of::<Event>() {
                        let event = unsafe { &*(bytes.as_ptr() as *const Event) };
                        
                        let proto_name = match event.protocol {
                            0x0800 => "IPv4",
                            0x0806 => "ARP",
                            0x86dd => "IPv6",
                            0x8100 => "VLAN",
                            0x88cc => "LLDP",
                            _ => "Other",
                        };
                        
                        // highlight QUIC packets
                        if event.is_quic == 1 {
                            let header_type = if event.is_long_header == 1 {
                                "Long"
                            } else {
                                "Short"
                            };
                            
                            println!(
                                "🔷 QUIC! pid={:<6} if={} len={:<5} {} hdr | CID v{} | {}",
                                event.pid,
                                event.ifindex,
                                event.pkt_len,
                                header_type,
                                event.cid_version,
                                proto_name,
                            );
                            println!("backend_id={} queue_id={} dcid_len={}", event.backend_id, event.queue_id, event.dcid_len);
                            println!("CID (first 20 bytes): {:02x?}", &event.cid[..]);
                        } else if event.is_udp == 1 {
                            // UDP (non-QUIC) packets with less prominence
                            println!(
                                "📤 UDP   pid={:<6} if={} len={:<5} {}",
                                event.pid,
                                event.ifindex,
                                event.pkt_len,
                                proto_name,
                            );
                        }
                        // show all packets 
                        // else {
                        //     println!(
                        //         "📦 pid={:<6} if={} len={:<5} {}",
                        //         event.pid,
                        //         event.ifindex,
                        //         event.pkt_len,
                        //         proto_name,
                        //     );
                        // }
                    }
                }
            }
        }
    }

    Ok(())
}
                    
