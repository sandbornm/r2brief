"""Unit tests for the static import verifier (analysis/verify.py)."""

from __future__ import annotations

from r2b.analysis.verify import (
    CallSite,
    ImportVerdict,
    extract_comment_string,
    first_arg_registers,
    parse_disassembly_line,
    resolve_argument,
    verify_imports,
)


class TestArgRegisters:
    def test_mips_family(self):
        assert first_arg_registers("mips") == ("a0",)

    def test_arm_family(self):
        assert first_arg_registers("arm") == ("r0",)
        assert first_arg_registers("aarch64") == ("x0", "w0")

    def test_x86_uses_rdi(self):
        assert first_arg_registers("x86") == ("rdi", "edi", "di")

    def test_unknown_arch_falls_back(self):
        regs = first_arg_registers(None)
        assert "a0" in regs and "rdi" in regs


class TestParseLine:
    def test_parses_addr_mnemonic_ops(self):
        line = "           0x0040eccc      2664c79c       addiu a0, s3, -0x3864       ; 0x41c79c ; \"getfirm MAC\""
        parsed = parse_disassembly_line(line)
        assert parsed is not None
        addr, mnem, ops = parsed
        assert addr == "0x0040eccc"
        assert mnem == "addiu"
        assert ops.startswith("a0, s3, -0x3864")

    def test_rejects_headers(self):
        assert parse_disassembly_line("┌ 596: sym.http_rpm_updateWlThroughput") is None
        assert parse_disassembly_line("(no output)") is None


class TestCommentFilter:
    def test_keeps_command_string(self):
        line = '  0x1  aa  addiu a0, s3, -1  ; "getfirm MAC"'
        assert extract_comment_string(line) == "getfirm MAC"

    def test_drops_source_location(self):
        assert extract_comment_string('  0x1  aa  lui a0, 0x42  ; ".c:215"') is None
        assert extract_comment_string('  0x1  aa  addiu a0, a0, 1  ; "tdpdServer.c:377"') is None


class TestResolveArgument:
    def test_constant_string_mips(self):
        lines = [
            "           0x0040eca8      3c130042       lui s3, 0x42                ; 0x420000 ; \".c:215\"",
            "           0x0040ecc8      24060200       addiu a2, zero, 0x200",
            "           0x0040eccc      2664c79c       addiu a0, s3, -0x3864       ; 0x41c79c ; \"getfirm MAC\"",
            "           0x0040ecd0      0c10092c       jal sym.imp.popen",
        ]
        site = resolve_argument(lines, len(lines) - 1, ("a0",))
        assert site.is_constant
        assert site.argument == "getfirm MAC"

    def test_dynamic_when_register_copied(self):
        lines = [
            "           0x0040d848      6c83998f       lw t9, -sym.imp.snprintf(gp)",
            "           0x0040d860      1800bc8f       lw gp, (var_18h)",
            "           0x0040d868      2000a427       addiu a0, sp, 0x20          ; arg1",
            "           0x0040d86c      5082998f       lw t9, -sym.imp.popen(gp)",
            "           0x0040d874      09f82003       jalr t9",
        ]
        site = resolve_argument(lines, len(lines) - 1, ("a0",))
        # Stack-relative address -> not a rodata constant.
        assert not site.is_constant

    def test_lui_without_string_comment_unresolved_pair(self):
        lines = [
            "           0x0040eccc      2664c79c       addiu a0, s3, -0x3864",
            "           0x0040ecd0      0c10092c       jal sym.imp.popen",
        ]
        site = resolve_argument(lines, len(lines) - 1, ("a0",))
        # No comment anywhere -> cannot claim constant.
        assert site.argument in ("<dynamic>", "<unresolved>")
        assert not site.is_constant


class TestVerdictStatus:
    def test_no_callers(self):
        v = ImportVerdict(import_name="system")
        assert v.status == "no-callers"

    def test_all_constant(self):
        v = ImportVerdict(
            import_name="popen",
            call_sites=[CallSite(function="f", address="0x1", argument="x", is_constant=True)],
        )
        assert v.status == "all-constant"

    def test_mixed(self):
        v = ImportVerdict(
            import_name="popen",
            call_sites=[
                CallSite(function="f", address="0x1", argument="x", is_constant=True),
                CallSite(function="g", address="0x2", argument="<dynamic>"),
            ],
        )
        assert v.status == "mixed"

    def test_to_dict_shape(self):
        v = ImportVerdict(import_name="popen", call_sites=[])
        d = v.to_dict()
        assert d["import"] == "popen"
        assert d["status"] == "no-callers"
        assert d["call_sites"] == []


class TestVerifyImports:
    def test_aarch64_bl_call(self):
        xref_lines = {
            "strcpy": [
                "           0x00400798      e10313aa       mov x1, x19",
                "           0x0040079c      e0430091       add x0, sp, 0x10",
                "; r2b-caller: sym.check_phrase",
                "           0x004007a0      dcffff97       bl sym.imp.strcpy",
            ]
        }
        verdicts = verify_imports(xref_lines, arch="arm")
        assert verdicts[0].status == "dynamic"
        assert verdicts[0].call_sites[0].address == "0x004007a0"
        assert verdicts[0].call_sites[0].function == "check_phrase"

    def test_end_to_end_mips_popen(self):
        xref_lines = {
            "popen": [
                "           0x0040eccc      2664c79c       addiu a0, s3, -0x3864       ; 0x41c79c ; \"getfirm MAC\"",
                "           0x0040ecd0      0c10092c       jal sym.imp.popen",
            ]
        }
        verdicts = verify_imports(xref_lines, arch="mips")
        assert len(verdicts) == 1
        assert verdicts[0].status == "all-constant"
        assert verdicts[0].call_sites[0].argument == "getfirm MAC"

    def test_empty_import_map(self):
        assert verify_imports({}, arch="mips") == []

    def test_call_line_not_counted_twice(self):
        # Two distinct call sites, second one dynamic.
        xref_lines = {
            "system": [
                "           0x0040c358      24a5b260       addiu a1, a1, -0x4da0       ; \"tplink_arp_fast_update disable\"",
                "           0x0040c360      2484b280       addiu a0, a0, -0x4d80       ; \"echo \\\"0\\\">/proc/tplink_arp_fast_update_enable\"",
                "           0x0040c364      0c100860       jal sym.imp.system",
                "           0x00412534      0c103dd2       jal fcn.0040f748",
                "           0x00412540      00408021       move a0, v0",
                "           0x00412544      0c102d34       jal sym.imp.system",
            ]
        }
        verdicts = verify_imports(xref_lines, arch="mips")
        assert len(verdicts[0].call_sites) == 2
        statuses = [cs.is_constant for cs in verdicts[0].call_sites]
        assert True in statuses and False in statuses
