#![no_std]
#![no_main]

mod common;

use aya_ebpf::{helpers::{bpf_get_current_pid_tgid, generated::bpf_ktime_get_ns}, macros::tracepoint, programs::TracePointContext};
use aya_log_ebpf::info;

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
    let ts = unsafe{ bpf_ktime_get_ns()};

    let event = Event{
        pid,
        timestamp: ts
    };
    
    if let Some(mut entry) = EVENTS.reserve::<Event>(0) {
        entry.write(event);
        entry.submit(0);
    }

    info!(&ctx, "execve from pid={}", pid);
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
