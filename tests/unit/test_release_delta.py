"""Unit tests for SHA-256 release-delta reduction."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from r2b.analysis.release_delta import (
    SCHEMA_VERSION,
    ChangedFile,
    FileEntry,
    compare_trees,
    file_sha256,
    index_tree,
    is_elf,
    iter_changed_elf_paths,
)
from r2b.cli import app

runner = CliRunner()


def _write(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _twin_trees(tmp_path: Path) -> tuple[Path, Path]:
    """Build a tiny vuln/patched rootfs pair for deterministic reduction."""
    a = tmp_path / "root_a"
    b = tmp_path / "root_b"
    _write(a / "etc" / "banner", b"OpenWrt same\n")
    _write(b / "etc" / "banner", b"OpenWrt same\n")
    _write(a / "etc" / "config" / "network", b"unchanged\n")
    _write(b / "etc" / "config" / "network", b"unchanged\n")
    _write(a / "usr" / "sbin" / "odhcpd", b"\x7fELF" + b"VULN-BUILD")
    _write(b / "usr" / "sbin" / "odhcpd", b"\x7fELF" + b"PATCH-BUILD")
    _write(a / "usr" / "bin" / "busybox", b"\x7fELF" + b"busybox-same")
    _write(b / "usr" / "bin" / "busybox", b"\x7fELF" + b"busybox-same")
    _write(a / "lib" / "firmware" / "blob.bin", b"fw-a")
    _write(b / "lib" / "firmware" / "blob.bin", b"fw-b")
    _write(a / "only_a.txt", b"gone in b")
    _write(b / "only_b.txt", b"new in b")
    # Symlink must not be indexed (noise).
    (a / "usr" / "sbin" / "odhcpd.symlink").symlink_to("odhcpd")
    (b / "usr" / "sbin" / "odhcpd.symlink").symlink_to("odhcpd")
    return a, b


class TestHelpers:
    def test_file_sha256_and_is_elf(self, tmp_path: Path) -> None:
        elf = _write(tmp_path / "bin", b"\x7fELF" + b"\x00" * 8)
        txt = _write(tmp_path / "note", b"hello")
        assert is_elf(elf) is True
        assert is_elf(txt) is False
        assert file_sha256(txt) == (
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        )

    def test_index_tree_skips_symlinks_and_uses_posix_paths(self, tmp_path: Path) -> None:
        root = tmp_path / "root"
        _write(root / "usr" / "sbin" / "x", b"\x7fELF" + b"x")
        (root / "link").symlink_to("usr/sbin/x")
        index = index_tree(root)
        assert "usr/sbin/x" in index
        assert "link" not in index
        assert index["usr/sbin/x"].is_elf is True

    def test_index_tree_requires_directory(self, tmp_path: Path) -> None:
        missing = tmp_path / "nope"
        with pytest.raises(FileNotFoundError):
            index_tree(missing)



    def test_is_elf_returns_false_on_oserror(self, tmp_path: Path) -> None:
        missing = tmp_path / "gone"
        assert is_elf(missing) is False


class TestCompareTrees:
    def test_reduction_isolates_changed_elfs(self, tmp_path: Path) -> None:
        a, b = _twin_trees(tmp_path)
        delta = compare_trees(a, b)
        reduction = delta.reduction()

        assert reduction == {
            "common_files": 5,  # banner, network, odhcpd, busybox, blob.bin
            "only_in_a": 1,
            "only_in_b": 1,
            "changed_common_files": 2,  # odhcpd + blob.bin
            "changed_common_elfs": 1,  # odhcpd only
            "unchanged_common_files": 3,
        }
        assert [item.relpath for item in delta.changed_elfs] == ["usr/sbin/odhcpd"]
        assert list(iter_changed_elf_paths(delta)) == ["usr/sbin/odhcpd"]
        assert delta.only_a == ("only_a.txt",)
        assert delta.only_b == ("only_b.txt",)

    def test_identical_trees_have_zero_changed(self, tmp_path: Path) -> None:
        a, b = _twin_trees(tmp_path)
        # Make B a byte-for-byte copy of A for shared paths.
        for rel in ("etc/banner", "etc/config/network", "usr/sbin/odhcpd", "usr/bin/busybox", "lib/firmware/blob.bin"):
            (b / rel).write_bytes((a / rel).read_bytes())
        (b / "only_a.txt").write_bytes((a / "only_a.txt").read_bytes())
        delta = compare_trees(a, b)
        # only_a / only_b may still differ; changed must be empty for common paths that match.
        assert delta.reduction()["changed_common_files"] == 0
        assert delta.changed_elfs == ()

    def test_to_dict_schema_and_optional_paths(self, tmp_path: Path) -> None:
        a, b = _twin_trees(tmp_path)
        delta = compare_trees(a, b)
        full = delta.to_dict(include_paths=True)
        slim = delta.to_dict(include_paths=False)

        assert full["schema_version"] == SCHEMA_VERSION
        assert "changed" in full and "only_a" in full
        assert "changed" not in slim and "only_b" not in slim
        assert slim["reduction"]["changed_common_elfs"] == 1
        elf = full["changed_elfs"][0]
        assert set(elf) == {
            "relpath",
            "a_sha256",
            "b_sha256",
            "a_size",
            "b_size",
            "is_elf",
        }
        assert elf["a_sha256"] != elf["b_sha256"]
        assert elf["is_elf"] is True

    def test_accepts_precomputed_indexes(self, tmp_path: Path) -> None:
        a, b = _twin_trees(tmp_path)
        a_index = index_tree(a)
        b_index = index_tree(b)
        delta = compare_trees(a, b, a_index=a_index, b_index=b_index)
        assert delta.reduction()["changed_common_elfs"] == 1

    def test_dataclass_round_trip_shapes(self) -> None:
        entry = FileEntry("x", "ab" * 32, True, 4)
        changed = ChangedFile("x", "ab" * 32, "cd" * 32, 4, 5, True)
        assert entry.to_dict()["size"] == 4
        assert changed.to_dict()["is_elf"] is True


class TestDiffCli:
    def test_diff_json_stdout(self, tmp_path: Path) -> None:
        a, b = _twin_trees(tmp_path)
        out = runner.invoke(app, ["diff", str(a), str(b), "--json"])
        assert out.exit_code == 0, out.output
        data = json.loads(out.stdout)
        assert data["schema_version"] == SCHEMA_VERSION
        assert data["reduction"]["changed_common_elfs"] == 1
        assert data["changed_elfs"][0]["relpath"] == "usr/sbin/odhcpd"

    def test_diff_missing_root_exits_nonzero(self, tmp_path: Path) -> None:
        a = tmp_path / "a"
        a.mkdir()
        out = runner.invoke(app, ["diff", str(a), str(tmp_path / "missing"), "--json"])
        assert out.exit_code == 1

    def test_diff_summary_text(self, tmp_path: Path) -> None:
        a, b = _twin_trees(tmp_path)
        out = runner.invoke(app, ["diff", str(a), str(b)])
        assert out.exit_code == 0, out.output
        assert "changed common ELFs" in out.stdout.lower() or "changed_common_elfs" in out.stdout or "Changed ELFs" in out.stdout
