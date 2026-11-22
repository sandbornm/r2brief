//! Synthetic Cortex-M firmware shapes from r2brief review findings.
//!
//! Each feature assembles one `Reset` / `main` shape. The user function
//! the triage must report is named in `tests/fixtures/cortex_m/manifest.json`.
#![no_std]
#![no_main]

use core::arch::global_asm;
use core::ptr::{read_volatile, write_volatile};

static mut FW_COUNTER: u32 = 0;
static mut FW_SEED: u32 = 0x1234_5678;

#[inline(never)]
#[no_mangle]
pub extern "C" fn fw_step(x: u32) -> u32 {
    x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223)
}

#[inline(never)]
#[no_mangle]
pub extern "C" fn fw_init() {
    unsafe { write_volatile(&raw mut FW_COUNTER, 0) };
}

#[inline(never)]
#[no_mangle]
pub extern "C" fn fw_pre_init() {
    unsafe { write_volatile(0x2000_3ff0 as *mut u32, 0xfeed_f00d) };
}

#[inline(never)]
#[no_mangle]
pub extern "C" fn fw_user_main() -> ! {
    let mut s = unsafe { read_volatile(&raw const FW_SEED) };
    loop {
        s = fw_step(s);
        unsafe { write_volatile(&raw mut FW_COUNTER, s) };
        if s == 0 {
            panic!("fw_edge: seed collapsed");
        }
    }
}

#[cfg(feature = "reset_b_main")]
#[no_mangle]
pub extern "C" fn main() -> ! {
    let mut s = unsafe { read_volatile(&raw const FW_SEED) };
    loop {
        s = fw_step(s ^ 0x5a5a);
        unsafe { write_volatile(&raw mut FW_COUNTER, s) };
    }
}

#[panic_handler]
fn on_panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

global_asm!(
    ".section .vector_table,\"a\",%progbits",
    ".word _stack_start",
    ".word Reset",
    ".text",
    ".syntax unified",
    ".thumb",
    ".global fw_exit",
    ".type fw_exit,%function",
    ".thumb_func",
    "fw_exit:",
    "    b fw_exit",
);

#[cfg(not(any(feature = "cbz_loop", feature = "reset_b_main", feature = "local_label")))]
global_asm!(
    ".text", ".syntax unified", ".thumb",
    ".global Reset", ".type Reset,%function", ".thumb_func",
    "Reset:",
    "    bl fw_init",
    "    bl main",
    "    udf #0",
);

// main: push; bl user; b.w exit
#[cfg(feature = "tail_exit")]
global_asm!(
    ".text", ".syntax unified", ".thumb",
    ".global main", ".type main,%function", ".thumb_func",
    "main:",
    "    push {{r7, lr}}",
    "    bl fw_user_main",
    "    b.w fw_exit",
);

// -O0-style two-call trampoline: bl __pre_init; bl user; udf
#[cfg(feature = "two_bl")]
global_asm!(
    ".text", ".syntax unified", ".thumb",
    ".global main", ".type main,%function", ".thumb_func",
    "main:",
    "    push {{r7, lr}}",
    "    mov r7, sp",
    "    bl fw_pre_init",
    "    bl fw_user_main",
    "    udf #0",
);

// Reset zeroes .bss in a loop whose exit is cbz.
#[cfg(feature = "cbz_loop")]
global_asm!(
    ".text", ".syntax unified", ".thumb",
    ".global Reset", ".type Reset,%function", ".thumb_func",
    "Reset:",
    "    ldr r0, =__sbss",
    "    ldr r1, =__ebss",
    "    movs r2, #0",
    "1:  subs r3, r1, r0",
    "    cbz r3, 2f",
    "    str r2, [r0], #4",
    "    b 1b",
    "2:  bl main",
    "    udf #0",
    "    .ltorg",
    ".global main", ".type main,%function", ".thumb_func",
    "main:",
    "    push {{r7, lr}}",
    "    bl fw_user_main",
    "    udf #0",
);

// Reset ends in a tail branch to a real (non-trampoline) main.
#[cfg(feature = "reset_b_main")]
global_asm!(
    ".text", ".syntax unified", ".thumb",
    ".global Reset", ".type Reset,%function", ".thumb_func",
    "Reset:",
    "    bl fw_init",
    "    b.w main",
);

// -Oz four-byte stub: main is `b.w` to the very next function.
#[cfg(feature = "bw_next")]
global_asm!(
    ".text", ".syntax unified", ".thumb",
    ".global main", ".type main,%function", ".thumb_func",
    "main:",
    "    b.w fw_user_loop",
    ".global fw_user_loop", ".type fw_user_loop,%function", ".thumb_func",
    "fw_user_loop:",
    "    push {{r4, lr}}",
    "    movs r4, #1",
    "1:  mov r0, r4",
    "    bl fw_step",
    "    mov r4, r0",
    "    b 1b",
);

// main is the user loop itself and opens with a forward branch to the loop test.
#[cfg(feature = "inlined_loop")]
global_asm!(
    ".text", ".syntax unified", ".thumb",
    ".global main", ".type main,%function", ".thumb_func",
    "main:",
    "    push {{r4, lr}}",
    "    movs r4, #1",
    "    b.n 2f",
    "1:  mov r0, r4",
    "    bl fw_step",
    "    mov r4, r0",
    "2:  cmp r4, #7",
    "    bne 1b",
    "    bl fw_init",
    "    b 1b",
);

// pre-init call, then a tail branch to a distant user function.
#[cfg(feature = "pre_init_tail")]
global_asm!(
    ".text", ".syntax unified", ".thumb",
    ".global main", ".type main,%function", ".thumb_func",
    "main:",
    "    push {{r7, lr}}",
    "    bl fw_pre_init",
    "    b.w fw_user_main",
);

// Reset: bl main; then a local forward branch over a nop to dead code.
#[cfg(feature = "local_label")]
global_asm!(
    ".text", ".syntax unified", ".thumb",
    ".global Reset", ".type Reset,%function", ".thumb_func",
    "Reset:",
    "    bl main",
    "    b 1f",
    "    nop",
    "1:  bl fw_init",
    "    udf #0",
    ".global main", ".type main,%function", ".thumb_func",
    "main:",
    "    push {{r7, lr}}",
    "    bl fw_user_main",
    "    udf #0",
);
