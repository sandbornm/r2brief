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


def test_pretty_symbol_keeps_malformed_names():
    """A bad or deeply nested symbol must not abort briefing demangle."""
    bad_unicode = "_ZN9$u110000$E"
    assert demangle(bad_unicode) is None
    assert pretty_symbol(bad_unicode) == bad_unicode
    deep = "_R" + "P" * 1200 + "u"
    assert demangle(deep) is None
    assert pretty_symbol(deep) == deep
    huge_binder = "_RIC3fooFG1iE_EuE"
    assert demangle(huge_binder) is None
    assert pretty_symbol(huge_binder) == huge_binder


def test_legacy_unicode_escape_in_range_still_decodes():
    assert demangle("_ZN5$u20$E") == " "


def test_demangle_bounds_exponential_backref_output():
    """Repeated tuple backrefs must not expand without a size budget."""
    # 76-byte symbol: each tuple duplicates the previous one. Without a cap
    # this grows to millions of characters; with the cap it is rejected.
    symbol = "_RIC3fooTuETB5_B5_ETB8_B8_ETBg_Bg_ETBo_Bo_ETBw_Bw_ETBE_BE_ETBM_BM_ETB1_B1_EE"
    assert len(symbol) < 200
    assert demangle(symbol) is None
    assert pretty_symbol(symbol) == symbol


def test_v0_integer_const_generics_decode_hex():
    """v0 const generics encode the value as hex and display it in decimal."""
    assert demangle("_RIC3fooKj10_E") == "foo::<16>"
    assert demangle("_RIC3fooKja_E") == "foo::<10>"
    assert demangle("_RIC3fooKjn10_E") == "foo::<-16>"


def test_v0_punycode_and_unsafe_fn_types():
    """Rust punycode uses '_' and the RFC 3492 digit alphabet; unsafe is kept."""
    assert demangle("_RCu7caf_dma") == "café"
    # RFC 2603: α_ω -> punycode _-ylb7e -> __ylb7e (7 bytes). A separator '_'
    # is required because the encoding starts with '_'. Prefix '_' stays '_'.
    assert demangle("_RCu7___ylb7e") == "α_ω"
    assert demangle("_RCu6f_5gaa") == "føø"
    assert demangle("_RIC3fooFUEuE") == "foo::<unsafe fn()>"
    assert demangle("_RIC3fooFEuE") == "foo::<fn()>"
