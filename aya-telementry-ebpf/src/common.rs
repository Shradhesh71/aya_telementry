use aya_ebpf::{macros::map, maps::RingBuf};

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Event {
    pub pid: u32,
    pub timestamp: u64,
}

#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);