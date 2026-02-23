#![no_std]

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Event {
    pub pid: u32,
    pub timestamp: u64,
    pub pkt_len: u32,
    pub ifindex: u32,
    pub protocol: u16,

    pub is_udp: u8,
    pub is_quic: u8,
    pub is_long_header: u8,

    pub cid_version: u8,
}
