#![no_std]
#![no_main]

mod common;

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

    let event = Event {
        pid,
        timestamp: ts,
        pkt_len: len,
        ifindex,
        protocol,
    };

    if let Some(mut entry) = EVENTS.reserve::<Event>(0) {
        entry.write(event);
        entry.submit(0);
    }

    info!(&ctx, "from pid: {},pkt: len={} proto=0x{:x} if={}", pid,len, protocol, ifindex);
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
