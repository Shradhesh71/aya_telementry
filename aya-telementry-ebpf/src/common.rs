use aya_ebpf::{macros::map, maps::RingBuf};

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

#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// #[repr(C)]
// pub struct SkBuff {
//     pub len: u32,
//     pub pkt_type: u32,
//     pub mark: u32,
//     pub queue_mapping: u16,
//     pub protocol: u16,
//     pub vlan_present: u8,
//     pub vlan_tci: u16,
//     pub vlan_proto: u16,
//     pub priority: u32,
//     pub skb_iif: u32,
// }