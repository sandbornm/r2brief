//! Synthetic cortex-m-rt firmware for r2brief triage fixtures.
#![no_std]
#![no_main]
#![allow(deprecated)]

use core::ptr::{read_volatile, write_volatile};
use cortex_m_rt::entry;
use panic_halt as _;

static mut FW_COUNTER: u32 = 0;
static mut FW_SEED: u32 = 0x1234_5678;

#[inline(never)]
#[no_mangle]
pub extern "C" fn fw_step(x: u32) -> u32 {
    x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223)
}

#[cfg(feature = "pre_init")]
#[cortex_m_rt::pre_init]
unsafe fn fw_pre_init() {
    write_volatile(0x2000_3ff0 as *mut u32, 0xfeed_f00d);
}

#[entry]
fn main() -> ! {
    let mut s = unsafe { read_volatile(&raw const FW_SEED) };
    loop {
        s = fw_step(s);
        unsafe { write_volatile(&raw mut FW_COUNTER, s) };
        if s == 0 {
            panic!("fw_demo: seed collapsed");
        }
    }
}
