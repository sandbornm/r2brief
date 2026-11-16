"""Rust symbol demangling. Vectors are standard spellings, not a corpus."""

from r2b.analysis.rustdemangle import demangle, pretty_symbol


def test_legacy_demangle_strips_hash_and_prefixes():
    assert demangle("_ZN3foo3bar17h0123456789abcdefE") == "foo::bar"
    assert demangle("_ZN3foo3barE") == "foo::bar"
    assert demangle("__ZN3foo3barE") == "foo::bar"
    assert demangle("sym._ZN3foo3barE") == "foo::bar"
    assert demangle("sym.imp._ZN3foo3barE") == "foo::bar"
    assert demangle("_ZN11$LT$foo$GT$3barE") == "<foo>::bar"


def test_legacy_demangle_rejects_truncated_symbols():
    assert demangle("_ZN3foo") is None
    assert demangle("_ZN3foo3barE.llvm.1") is None
    assert pretty_symbol("_ZN3foo3barE.llvm.1") == "_ZN3foo3barE.llvm.1"


def test_v0_paths_generics_and_impls():
    assert demangle("_RNvCsjGg8ogh6BAv_6ac_cli4main") == "ac_cli::main"
    assert (
        demangle("_RINvNtCscp9wYLKclqE_4core9panicking13assert_failedllECs5zxP6yxRqCi_3std")
        == "core::panicking::assert_failed::<i32, i32>"
    )
    assert demangle("_RNvMCsjBuPJAFrEDO_7fw_uartNtB2_4Uart12fw_uart_init") == (
        "<fw_uart::Uart>::fw_uart_init"
    )
    assert (
        demangle(
            "_RNvXs_CsjBuPJAFrEDO_7fw_uartNtB4_4UartNtNtCs2Y5aVkZPKTG_4core3fmt5Write9write_str"
        )
        == "<fw_uart::Uart as core::fmt::Write>::write_str"
    )
    assert (
        demangle(
            "_RNvYNtCsjBuPJAFrEDO_7fw_uart4UartNtNtCs2Y5aVkZPKTG_4core3fmt5Write10write_charB4_"
        )
        == "<fw_uart::Uart as core::fmt::Write>::write_char"
    )


def test_pretty_symbol_leaves_plain_names():
    assert pretty_symbol("malloc") == "malloc"
    assert demangle("not_a_symbol") is None
    assert demangle("_Rnotreally") is None
    assert demangle("") is None
