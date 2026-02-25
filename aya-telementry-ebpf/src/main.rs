#![no_std]
#![no_main]

mod common;

const NUM_QUEUES: u16 = 64;

use aya_ebpf::{helpers::{bpf_get_current_pid_tgid, generated::bpf_ktime_get_ns}, macros::tracepoint, programs::TracePointContext};
use aya_log_ebpf::info;
use aya_ebpf::helpers::bpf_probe_read_kernel;

use crate::common::{EVENTS, Event};

#[tracepoint]
pub fn aya_telementry(ctx: TracePointContext) -> u32 {
    match try_aya_telementry(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_aya_telementry(ctx: TracePointContext) -> Result<u32, u32> {
    let pid =( bpf_get_current_pid_tgid() >> 32) as u32;
    let ts = unsafe { bpf_ktime_get_ns() };

    // read fields directly from tracepoint context
    // offset 8: skbaddr (pointer to sk_buff)
    // offset 16: len (packet length) - directly exposed by tracepoint!
    let skb_ptr: *const u8 = unsafe { ctx.read_at::<*const u8>(8).map_err(|_| 1u32)? };
    let len: u32 = unsafe { ctx.read_at::<u32>(16).map_err(|_| 1u32)? };

    // read from sk_buff structure at correct offsets (for kernel 6.17 x86_64):
    // - protocol at offset 180 (__be16, needs byte swap on little-endian)
    // - skb_iif at offset 220 (interface index)
    let protocol_raw: u16 = unsafe {
        bpf_probe_read_kernel(skb_ptr.add(180) as *const u16).unwrap_or(0)
    };
    
    let ifindex: u32 = unsafe {
        bpf_probe_read_kernel(skb_ptr.add(220) as *const u32).unwrap_or(0)
    };

    // convert protocol from network byte order (stored as __be16 in sk_buff)
    // on x86_64 little-endian, we need to swap bytes to get standard protocol numbers
    let protocol = protocol_raw.swap_bytes();

    // QUIC detection variables
    let mut is_udp = 0u8;
    let mut is_quic = 0u8;
    let mut is_long = 0u8;
    let mut cid_version = 0u8;

    let mut dcid_len:u8 = 0;
    let mut backend_id: u16 = 0;
    let mut queue_id: u16 = 0;

    let mut cid_data = [0u8; 20];

    // Read sk_buff.data pointer (offset varies, typically around 216 for kernel 6.x)
    // This points to the start of packet data
    let data_ptr: *const u8 = unsafe {
        bpf_probe_read_kernel(skb_ptr.add(216) as *const *const u8).unwrap_or(core::ptr::null())
    };

    // Only parse if we have enough data for Ethernet + IP + UDP + QUIC headers
    if !data_ptr.is_null() && len > 42 {
        // Read first 64 bytes of packet data
        // We need to read byte by byte since bpf_probe_read_kernel returns a single value
        let mut pkt_data = [0u8; 64];
        
        unsafe {
            // Read packet data in chunks or use a safer approach
            for i in 0..64 {
                if let Ok(byte) = bpf_probe_read_kernel(data_ptr.add(i) as *const u8) {
                    pkt_data[i] = byte;
                } else {
                    break;
                }
            }
        }

        // parse based on Ethernet type
        // assuming no VLAN for now
        
        // check if IPv4 (protocol 0x0800) or IPv6 (0x86dd)
        if protocol == 0x0800 {
            // IPv4: IP protocol field is at offset 9 in IP header (offset 14+9=23 from Ethernet)
            let ip_proto = pkt_data[23];
            
            if ip_proto == 17 {
                is_udp = 1;

                // UDP header starts at offset 14 (Ethernet) + 20 (IPv4 min) = 34
                // UDP dest port is at offset 34 + 2 = 36 (2 bytes, big endian)
                let udp_dest_port = ((pkt_data[36] as u16) << 8) | (pkt_data[37] as u16);

                // Check for common QUIC ports: 443 (HTTPS), 4433 
                if udp_dest_port == 443 || udp_dest_port == 4433 {
                    // QUIC payload starts after UDP header (8 bytes)
                    // Offset: 14 (Eth) + 20 (IP) + 8 (UDP) = 42
                    let quic_offset = 42;

                    if quic_offset < 64 {
                        let quic_flags = pkt_data[quic_offset];

                        // QUIC packets have specific flag patterns
                        // Long header: bit 7 (0x80) is set
                        // Short header: bit 7 is not set
                        
                        // Check if it looks like QUIC (either long or short header)
                        // Long header always has 0x80 set
                        if quic_flags & 0x80 != 0 {
                            is_quic = 1;
                            is_long = 1;

                            // In QUIC long header:
                            // Byte 0: flags
                            // Bytes 1-4: version
                            // Byte 5: DCID len
                            // Byte 6+: DCID (first byte is our CID version)
                            if quic_offset + 6 < 64 {
                                cid_version = pkt_data[quic_offset + 6];
                            }
                            dcid_len = pkt_data[quic_offset + 5];
                            // CID (8 bytes)
                            // [0] version 
                            // [1] flags
                            // [2] backend_id (MSB)
                            // [3] backend_id (LSB)
                            // [4..] random salt
                            if dcid_len >= 4 && quic_offset + 9 < 64 {
                                backend_id = ((pkt_data[quic_offset + 2] as u16) << 8) | (pkt_data[quic_offset + 3] as u16);
                                queue_id = backend_id % NUM_QUEUES;
                            }
                            cid_data.copy_from_slice(&pkt_data[quic_offset + 6..quic_offset + 6 + core::cmp::min(dcid_len as usize, 20)]);
                        } else if quic_flags & 0x40 != 0 {
                            // Short header: bit 6 (0x40) set, bit 7 clear
                            // This is a heuristic - short headers don't have a fixed pattern
                            is_quic = 1;
                            is_long = 0;
                            // Short headers don't expose CID version easily
                        }
                    }
                }
            }
        } else if protocol == 0x86dd {
            // IPv6: Next header field is at offset 6 in IPv6 header (offset 14+6=20)
            let ip_proto = pkt_data[20];
            
            if ip_proto == 17 {
                is_udp = 1;

                // UDP header starts at offset 14 (Ethernet) + 40 (IPv6) = 54
                // But we only read 64 bytes, so be careful
                if len > 54 + 8 {
                    let udp_dest_port = ((pkt_data[56] as u16) << 8) | (pkt_data[57] as u16);

                    if udp_dest_port == 443 || udp_dest_port == 4433 || udp_dest_port == 8000 {
                        // QUIC offset: 14 (Eth) + 40 (IPv6) + 8 (UDP) = 62
                        let quic_offset = 62;

                        if quic_offset < 64 {
                            let quic_flags = pkt_data[quic_offset];

                            if quic_flags & 0x80 != 0 {
                                is_quic = 1;
                                is_long = 1;
                                // Can't read CID safely with only 64 bytes for IPv6
                            } else if quic_flags & 0x40 != 0 {
                                is_quic = 1;
                                is_long = 0;
                            }
                        }
                    }
                }
            }
        }
    }

    let event = Event {
        pid,
        timestamp: ts,
        pkt_len: len,
        ifindex,
        protocol,
        is_udp,
        is_quic,
        is_long_header: is_long,
        cid_version,
        dcid_len,
        backend_id,
        queue_id,
        cid: cid_data,
    };

    if let Some(mut entry) = EVENTS.reserve::<Event>(0) {
        entry.write(event);
        entry.submit(0);
    }

    if is_quic == 1 {
        info!(&ctx, "QUIC detected! pid={} len={} long={} cid_ver={}", 
              pid, len, is_long, cid_version);
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
