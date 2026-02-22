#![no_std]

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Event {
    pub pid: u32,
    pub timestamp: u64,
    pub pkt_len: u32,
    pub ifindex: u32,
    pub protocol: u16,
}
