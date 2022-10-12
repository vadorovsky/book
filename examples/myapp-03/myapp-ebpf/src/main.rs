#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;

use core::mem;
use memoffset::offset_of;

mod bindings;
use bindings::{ethhdr, iphdr};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[map(name = "BLOCKLIST")] // (1)
static BLOCKLIST: HashMap<u32, u32> =
    HashMap::<u32, u32>::with_max_entries(1024, 0);

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

// (2)
fn block_ip(address: u32) -> bool {
    unsafe { BLOCKLIST.get(&address).is_some() }
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let h_proto =
        u16::from_be(unsafe { *ptr_at(&ctx, offset_of!(ethhdr, h_proto))? });
    if h_proto != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }
    let source = u32::from_be(unsafe {
        *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, saddr))?
    });

    // (3)
    let action = if block_ip(source) {
        info!(&ctx, "src: {:ipv4}, action: drop", source);
        xdp_action::XDP_DROP
    } else {
        info!(&ctx, "src: {:ipv4}, action: pass", source);
        xdp_action::XDP_PASS
    };
    Ok(action)
}

const ETH_P_IP: u16 = 0x0800;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
