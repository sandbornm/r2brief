"""HTTP-level checks: path confinement, option allowlists and generic error bodies."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

pytest.importorskip("flask")

ELF = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + b"\x02\x00\x3e\x00\x01\x00\x00\x00" + b"\x00" * 48


@pytest.fixture
def web(tmp_path: Path):
    """Flask test client plus the directories it is allowed to read from."""
    from r2b.config import AnalysisSettings, AppConfig, OutputSettings, StorageSettings
    from r2b.web.app import create_app

    config = AppConfig()
    config.storage = StorageSettings(database_path=tmp_path / "t.db", auto_migrate=True)
    config.analysis = AnalysisSettings(enable_angr=False, enable_ghidra=False, require_elf=False)
    config.output = OutputSettings(artifacts_dir=tmp_path / "artifacts")
    uploads = tmp_path / "artifacts" / "uploads"
    with patch("r2b.state.load_config", return_value=config):
        app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client, uploads, tmp_path


# --- /api/analyze ---------------------------------------------------------------------


def test_analyze_accepts_uploaded_binary(web) -> None:
    client, uploads, _ = web
    binary = uploads / "ok.elf"
    binary.write_bytes(ELF)
    response = client.post("/api/analyze", json={"binary": str(binary), "quick_only": True})
    assert response.status_code == 200
    assert response.get_json()["session_id"]


@pytest.mark.parametrize("candidate", ["/etc/passwd", "../../etc/passwd", "uploads/../../../etc/passwd", "bad\x00name"])
def test_analyze_rejects_paths_outside_uploads(web, candidate: str) -> None:
    client, _, _ = web
    response = client.post("/api/analyze", json={"binary": candidate})
    assert response.status_code == 404
    # Identical body for "missing" and "not allowed": no filesystem probing.
    assert response.get_json() == {"error": "Binary not found in an allowed directory"}


def test_analyze_rejects_symlink_pointing_outside_uploads(web) -> None:
    client, uploads, tmp_path = web
    secret = tmp_path / "secret.bin"
    secret.write_bytes(ELF)
    uploads.mkdir(parents=True, exist_ok=True)
    (uploads / "link.elf").symlink_to(secret)
    response = client.post("/api/analyze", json={"binary": str(uploads / "link.elf")})
    assert response.status_code == 404


def test_allowed_roots_config_opts_in_extra_directories(tmp_path: Path) -> None:
    from r2b.config import AnalysisSettings, AppConfig, OutputSettings, StorageSettings
    from r2b.web.app import create_app

    corpus = tmp_path / "corpus"
    corpus.mkdir()
    sample = corpus / "s.elf"
    sample.write_bytes(ELF)
    config = AppConfig()
    config.storage = StorageSettings(database_path=tmp_path / "t.db", auto_migrate=True)
    config.analysis = AnalysisSettings(enable_angr=False, enable_ghidra=False, require_elf=False)
    config.output = OutputSettings(artifacts_dir=tmp_path / "artifacts")
    config.web.allowed_roots = [corpus]
    with patch("r2b.state.load_config", return_value=config):
        app = create_app()
    with app.test_client() as client:
        assert client.post("/api/analyze", json={"binary": str(sample), "quick_only": True}).status_code == 200


# --- /api/compile ---------------------------------------------------------------------


def test_compile_rejects_unlisted_optimization_and_architecture(web) -> None:
    client, _, _ = web
    assert client.post("/api/compile", json={"source": "int x;", "optimization": "-fplugin=/tmp/x.so"}).status_code == 400
    assert client.post("/api/compile", json={"source": "int x;", "optimization": "-O0; id"}).status_code == 400
    assert client.post("/api/compile", json={"source": "int x;", "architecture": "arm64; id"}).status_code == 400
    assert client.post("/api/compile", json={"source": "int x;", "type": "../x"}).status_code == 400


def test_compile_source_path_must_be_inside_uploads(web) -> None:
    client, uploads, tmp_path = web
    outside = tmp_path / "outside.c"
    outside.write_text("int secret_marker;")
    for candidate in (str(outside), "../outside.c", "/etc/passwd"):
        response = client.post("/api/compile", json={"source_path": candidate, "architecture": "x86_64"})
        assert response.status_code == 404
        assert "secret_marker" not in response.get_data(as_text=True)


def test_compile_inline_source_that_looks_like_a_path_is_not_read(web) -> None:
    client, _, tmp_path = web
    secret = tmp_path / "secret.c"
    secret.write_text("int secret_marker_xyz;")
    response = client.post(
        "/api/compile",
        json={"source": str(secret), "architecture": "x86_64", "emit_asm": True},
    )
    assert "secret_marker_xyz" not in response.get_data(as_text=True)


def test_compile_output_name_cannot_escape_uploads(web, monkeypatch: pytest.MonkeyPatch) -> None:
    client, uploads, tmp_path = web
    from r2b.compilation import compiler as comp

    seen: dict[str, Path | None] = {}

    def fake_compile(source, architecture, output=None, optimization="-O0", extra_flags=None, **kwargs):  # noqa: ANN001
        seen["output"] = output
        return comp.CompilerResult(success=False, stderr="stub", architecture=architecture)

    monkeypatch.setattr("r2b.compilation.compile_c_source", fake_compile)
    client.post(
        "/api/compile",
        json={"source": "int x;", "architecture": "x86_64", "output_name": "../../../tmp/evil", "emit_asm": False},
    )
    output = seen["output"]
    assert output is not None
    assert output.parent == uploads
    assert output.name == "evil"


def test_compile_preview_rejects_bad_options_with_generic_error(web) -> None:
    client, _, _ = web
    response = client.post("/api/compilers/preview", json={"optimization": "-O0; id", "architecture": "arm64"})
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["available"] is False
    assert "; id" not in payload["command"]


# --- error bodies ---------------------------------------------------------------------


def test_record_errors_do_not_echo_exception_text(web) -> None:
    client, _, _ = web
    response = client.get("/api/records/..%2F..%2Fetc")
    assert response.status_code in (400, 404)
    assert "Traceback" not in response.get_data(as_text=True)
    bad = client.get("/api/records/bad id?format=json")
    if bad.status_code == 400:
        assert bad.get_json() == {"error": "Invalid record id"}


def test_download_filename_is_header_safe(web) -> None:
    from r2b.web.app import _download_filename

    class _Session:
        binary_path = '/tmp/evil"\r\nSet-Cookie: x=1.elf'
        session_id = "abc"

    name = _download_filename(_Session(), "-r2b-report.md")  # type: ignore[arg-type]
    assert '"' not in name and "\r" not in name and "\n" not in name and " " not in name
    assert name.endswith("-r2b-report.md")


def test_headless_script_binary_must_be_inside_allowed_roots(web) -> None:
    from r2b.web.app import _execute_script_headless
    from unittest.mock import MagicMock

    _, uploads, tmp_path = web
    state = MagicMock()
    state.env.ghidra.is_ready = True
    state.config.output.artifacts_dir = tmp_path / "artifacts"
    state.config.web.allowed_roots = []
    with pytest.raises(RuntimeError, match="allowed directory"):
        _execute_script_headless("print(1)", "python", "/etc/passwd", state)
    # A bare option-looking value is anchored under the upload dir, so it is never a flag.
    with pytest.raises(RuntimeError, match="not a file"):
        _execute_script_headless("print(1)", "python", "-help", state)


def test_headless_script_receives_absolute_confined_path(web) -> None:
    import subprocess
    from unittest.mock import MagicMock

    from r2b.web.app import _execute_script_headless

    _, uploads, tmp_path = web
    uploads.mkdir(parents=True, exist_ok=True)
    binary = uploads / "ok.elf"
    binary.write_bytes(ELF)
    state = MagicMock()
    state.env.ghidra.is_ready = True
    state.env.ghidra.headless_path = "/opt/ghidra/support/analyzeHeadless"
    state.config.output.artifacts_dir = tmp_path / "artifacts"
    state.config.web.allowed_roots = []
    state.config.ghidra.project_dir = tmp_path / "proj"
    with patch.object(subprocess, "run") as run:
        run.return_value = subprocess.CompletedProcess([], 0, stdout="ok", stderr="")
        _execute_script_headless("print(1)", "python", "ok.elf", state)
    argv = run.call_args.args[0]
    assert argv[argv.index("-import") + 1] == str(binary.resolve())
