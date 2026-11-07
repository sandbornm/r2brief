from __future__ import annotations

import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

pytestmark = pytest.mark.integration

if TYPE_CHECKING:
    pass


HELLO_C = """\
#include <stdio.h>

int main(void) {
    puts("Hello, ARM World!");
    return 0;
}
"""

FIBONACCI_C = """\
int fib(int n) {
    if (n <= 1) return n;
    return fib(n - 1) + fib(n - 2);
}

int main(void) {
    volatile int result = fib(10);
    return (int)result;
}
"""

FREESTANDING_C = """\
// Freestanding ARM64 Hello World
// Uses direct syscalls to write and exit

static const char msg[] = "Hello from ARM64!\\n";

void _start(void) {
    // syscall: write(1, msg, sizeof(msg)-1)
    register long x0 __asm__("x0") = 1;           // fd = stdout
    register long x1 __asm__("x1") = (long)msg;   // buf
    register long x2 __asm__("x2") = sizeof(msg) - 1;
    register long x8 __asm__("x8") = 64;          // __NR_write
    __asm__ volatile("svc #0" : : "r"(x0), "r"(x1), "r"(x2), "r"(x8));

    // syscall: exit(0)
    x0 = 0;
    x8 = 93;  // __NR_exit
    __asm__ volatile("svc #0" : : "r"(x0), "r"(x8));
    __builtin_unreachable();
}
"""

FREESTANDING_ARM32_C = """\
// Freestanding ARM32 program
// Minimal example without inline asm register constraints

void _start(void) {
    // Simple infinite loop - just tests that we can compile freestanding
    volatile int x = 42;
    while(1) {
        x++;
    }
}
"""

BROKEN_C = """\
int main(void) {
    undefined_function();  // This will cause an error
    return 0;
}
"""

LOOP_C = """\
int main(void) {
    volatile int sum = 0;
    for (int i = 0; i < 100; i++) {
        sum += i;
    }
    return sum;
}
"""


@pytest.fixture(scope="module")
def docker_available() -> bool:
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


@pytest.fixture(scope="module")
def compiler_image_ready(docker_available: bool) -> bool:
    if not docker_available:
        return False
    try:
        result = subprocess.run(
            ["docker", "image", "inspect", "r2b-compiler:latest"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


@pytest.fixture
def temp_output_dir(tmp_path: Path) -> Path:
    output_dir = tmp_path / "compiler_output"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


@pytest.fixture
def sample_c_file(tmp_path: Path) -> Path:
    c_file = tmp_path / "test.c"
    c_file.write_text(FIBONACCI_C)
    return c_file


class TestDockerDetection:

    def test_docker_check_utility(self, docker_available: bool):
        from r2b.compilation.compiler import _is_docker_available
        
        result = _is_docker_available()
        assert result == docker_available

    @pytest.mark.skipif(
        subprocess.run(["docker", "info"], capture_output=True).returncode != 0,
        reason="Docker not available"
    )
    def test_docker_image_check(self, compiler_image_ready: bool):
        from r2b.compilation.compiler import _docker_image_exists, DOCKER_COMPILER_IMAGE
        
        result = _docker_image_exists(DOCKER_COMPILER_IMAGE)
        assert result == compiler_image_ready

    def test_detect_compilers_includes_docker(self, compiler_image_ready: bool):
        from r2b.compilation.compiler import detect_compilers
        
        compilers = detect_compilers(include_docker=True)
        
        assert "arm64" in compilers
        assert "arm32" in compilers
        assert "x86" in compilers
        assert "x86_64" in compilers

        if compiler_image_ready:
            assert len(compilers["arm64"]) > 0 or len(compilers["arm32"]) > 0


@pytest.mark.skipif(
    subprocess.run(["docker", "image", "inspect", "r2b-compiler:latest"],
                   capture_output=True).returncode != 0,
    reason="Compiler Docker image not available"
)
class TestARM64Compilation:

    def test_compile_simple_program(self, temp_output_dir: Path):
        from r2b.compilation.compiler import compile_c_source
        
        output_path = temp_output_dir / "fibonacci_arm64"
        result = compile_c_source(
            source=FIBONACCI_C,
            architecture="arm64",
            output=output_path,
            optimization="-O0",
        )
        
        assert result.success, f"Compilation failed: {result.stderr}"
        assert result.output_path is not None
        assert result.output_path.exists()
        assert result.architecture == "arm64"
        assert "aarch64" in result.compiler_used.lower() or "docker" in result.compiler_used.lower()

    def test_compile_file_path(self, sample_c_file: Path, temp_output_dir: Path):
        from r2b.compilation.compiler import compile_c_source
        
        output_path = temp_output_dir / "from_file"
        result = compile_c_source(
            source=sample_c_file,
            architecture="arm64",
            output=output_path,
        )
        
        assert result.success, f"Compilation failed: {result.stderr}"
        assert result.output_path is not None

    def test_compile_with_optimization(self, temp_output_dir: Path):
        from r2b.compilation.compiler import compile_c_source
        
        for opt in ["-O0", "-O1", "-O2", "-O3", "-Os"]:
            output_path = temp_output_dir / f"opt_{opt.replace('-', '')}"
            result = compile_c_source(
                source=LOOP_C,
                architecture="arm64",
                output=output_path,
                optimization=opt,
            )
            
            assert result.success, f"Compilation with {opt} failed: {result.stderr}"

    def test_compile_freestanding_arm64(self, temp_output_dir: Path):
        from r2b.compilation.compiler import compile_c_source
        
        output_path = temp_output_dir / "freestanding_arm64"
        result = compile_c_source(
            source=FREESTANDING_C,
            architecture="arm64",
            output=output_path,
            extra_flags=["-ffreestanding", "-nostdlib", "-static"],
        )
        
        assert result.success, f"Freestanding compilation failed: {result.stderr}"
        assert result.output_path is not None
        assert result.output_path.exists()

    def test_generate_assembly_arm64(self, temp_output_dir: Path):
        from r2b.compilation.compiler import compile_to_asm
        
        result = compile_to_asm(
            source=FIBONACCI_C,
            architecture="arm64",
            optimization="-O0",
        )
        
        assert result.success, f"Assembly generation failed: {result.stderr}"
        assert result.assembly is not None
        
        asm = result.assembly
        assert any(pattern in asm.lower() for pattern in [
            ".text",
            "stp", "ldp",
            "bl ", "ret",
            "x0", "x1",
            "w0", "w1",
        ]), f"Assembly doesn't look like ARM64:\n{asm[:500]}"

    def test_verify_elf_format(self, temp_output_dir: Path):
        from r2b.compilation.compiler import compile_c_source
        
        output_path = temp_output_dir / "verify_elf"
        result = compile_c_source(
            source=FIBONACCI_C,
            architecture="arm64",
            output=output_path,
        )
        
        assert result.success
        assert result.output_path is not None
        
        with open(result.output_path, "rb") as f:
            header = f.read(20)
        
        assert header[:4] == b"\x7fELF", "Not an ELF file"
        assert header[4] == 2, "Not a 64-bit ELF"
        assert header[5] == 1, "Not little-endian"
        machine = int.from_bytes(header[18:20], "little")
        assert machine == 183, f"Not an ARM64 binary (machine type: {machine})"


@pytest.mark.skipif(
    subprocess.run(["docker", "image", "inspect", "r2b-compiler:latest"],
                   capture_output=True).returncode != 0,
    reason="Compiler Docker image not available"
)
class TestARM32Compilation:

    def test_compile_simple_program_arm32(self, temp_output_dir: Path):
        from r2b.compilation.compiler import compile_c_source
        
        output_path = temp_output_dir / "fibonacci_arm32"
        result = compile_c_source(
            source=FIBONACCI_C,
            architecture="arm32",
            output=output_path,
            optimization="-O0",
        )
        
        assert result.success, f"ARM32 compilation failed: {result.stderr}"
        assert result.output_path is not None
        assert result.architecture == "arm32"

    def test_compile_freestanding_arm32(self, temp_output_dir: Path):
        from r2b.compilation.compiler import compile_c_source
        
        output_path = temp_output_dir / "freestanding_arm32"
        result = compile_c_source(
            source=FREESTANDING_ARM32_C,
            architecture="arm32",
            output=output_path,
            extra_flags=["-ffreestanding", "-nostdlib", "-static"],
        )
        
        assert result.success, f"ARM32 freestanding compilation failed: {result.stderr}"

    def test_verify_arm32_elf_format(self, temp_output_dir: Path):
        from r2b.compilation.compiler import compile_c_source
        
        output_path = temp_output_dir / "verify_arm32_elf"
        result = compile_c_source(
            source=FIBONACCI_C,
            architecture="arm32",
            output=output_path,
        )
        
        assert result.success
        assert result.output_path is not None
        
        with open(result.output_path, "rb") as f:
            header = f.read(20)
        
        assert header[:4] == b"\x7fELF", "Not an ELF file"
        assert header[4] == 1, "Not a 32-bit ELF"
        machine = int.from_bytes(header[18:20], "little")
        assert machine == 40, f"Not an ARM32 binary (machine type: {machine})"


class TestCompilerErrors:

    @pytest.mark.skipif(
        subprocess.run(["docker", "image", "inspect", "r2b-compiler:latest"],
                       capture_output=True).returncode != 0,
        reason="Compiler Docker image not available"
    )
    def test_compilation_error_reported(self, temp_output_dir: Path):
        from r2b.compilation.compiler import compile_c_source
        
        output_path = temp_output_dir / "broken"
        result = compile_c_source(
            source=BROKEN_C,
            architecture="arm64",
            output=output_path,
        )
        
        assert not result.success
        assert result.return_code != 0
        assert "undefined" in result.stderr.lower() or "undeclared" in result.stderr.lower()

    def test_docker_not_available_error(self, monkeypatch):
        from r2b.compilation import compiler
        
        monkeypatch.setattr(compiler, "_is_docker_available", lambda: False)
        monkeypatch.setattr(compiler, "detect_compilers", lambda include_docker=True: {
            "arm64": [],
            "arm32": [],
            "x86": [],
            "x86_64": [],
        })
        
        from r2b.compilation.compiler import compile_c_source
        
        result = compile_c_source(
            source=FIBONACCI_C,
            architecture="arm64",
        )
        
        assert not result.success
        assert "docker" in result.stderr.lower() or "compiler" in result.stderr.lower()

    def test_invalid_source_file(self, temp_output_dir: Path):
        from r2b.compilation.compiler import compile_c_source
        
        result = compile_c_source(
            source=Path("/nonexistent/path/to/source.c"),
            architecture="arm64",
            output=temp_output_dir / "output",
        )
        
        assert not result.success


@pytest.mark.skipif(
    subprocess.run(["docker", "image", "inspect", "r2b-compiler:latest"],
                   capture_output=True).returncode != 0,
    reason="Compiler Docker image not available"
)
class TestCompilerAPI:

    @pytest.fixture
    def app_client(self, tmp_path: Path):
        from unittest.mock import patch
        from r2b.web.app import create_app
        from r2b.config import AppConfig, StorageSettings, AnalysisSettings

        with patch.dict('os.environ', {'R2B_WEB_DEBUG': 'false'}):
            with patch('r2b.config.load_config') as mock_config:
                test_config = AppConfig()
                test_config.storage = StorageSettings(
                    database_path=tmp_path / "test.db",
                    auto_migrate=True,
                )
                test_config.analysis = AnalysisSettings(
                    enable_angr=False,
                    enable_ghidra=False,
                    require_elf=False,
                )
                mock_config.return_value = test_config

                app = create_app()
                app.config['TESTING'] = True

                with app.test_client() as client:
                    yield client

    def test_list_compilers_endpoint(self, app_client):
        response = app_client.get('/api/compilers')
        
        assert response.status_code == 200
        data = response.get_json()
        assert "compilers" in data
        assert "arm64" in data["compilers"]
        assert "arm32" in data["compilers"]

    def test_compile_endpoint_requires_source(self, app_client):
        response = app_client.post(
            '/api/compile',
            json={"architecture": "arm64"},
            content_type='application/json',
        )
        
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data

    def test_compile_endpoint_arm64(self, app_client):
        response = app_client.post(
            '/api/compile',
            json={
                "source": FIBONACCI_C,
                "architecture": "arm64",
                "optimization": "-O0",
                "emit_asm": True,
            },
            content_type='application/json',
        )
        
        assert response.status_code == 200, f"Compile failed: {response.get_json()}"
        data = response.get_json()
        assert data["success"] is True
        assert "output_path" in data
        assert data["architecture"] == "arm64"
        assert "assembly" in data

    def test_compile_endpoint_arm32(self, app_client):
        response = app_client.post(
            '/api/compile',
            json={
                "source": FIBONACCI_C,
                "architecture": "arm32",
                "optimization": "-O0",
            },
            content_type='application/json',
        )
        
        assert response.status_code == 200, f"Compile failed: {response.get_json()}"
        data = response.get_json()
        assert data["success"] is True
        assert data["architecture"] == "arm32"

    def test_compile_endpoint_freestanding(self, app_client):
        response = app_client.post(
            '/api/compile',
            json={
                "source": FREESTANDING_C,
                "architecture": "arm64",
                "freestanding": True,
            },
            content_type='application/json',
        )
        
        assert response.status_code == 200, f"Compile failed: {response.get_json()}"
        data = response.get_json()
        assert data["success"] is True

    def test_compile_endpoint_error_handling(self, app_client):
        response = app_client.post(
            '/api/compile',
            json={
                "source": BROKEN_C,
                "architecture": "arm64",
            },
            content_type='application/json',
        )
        
        assert response.status_code == 400
        data = response.get_json()
        assert data["success"] is False
        assert "stderr" in data
        assert len(data["stderr"]) > 0


@pytest.mark.skipif(
    subprocess.run(["docker", "image", "inspect", "r2b-compiler:latest"],
                   capture_output=True).returncode != 0,
    reason="Compiler Docker image not available"
)
class TestSamplePrograms:

    @pytest.fixture
    def samples_dir(self) -> Path:
        project_root = Path(__file__).parent.parent.parent
        samples = project_root / "samples" / "c"
        if not samples.exists():
            pytest.skip("samples/c directory not found")
        return samples

    def test_compile_hello_c(self, samples_dir: Path, temp_output_dir: Path):
        from r2b.compilation.compiler import compile_c_source
        
        hello_c = samples_dir / "hello.c"
        if not hello_c.exists():
            pytest.skip("hello.c not found")
        
        result = compile_c_source(
            source=hello_c,
            architecture="arm64",
            output=temp_output_dir / "hello",
        )
        
        assert result.success, f"Failed to compile hello.c: {result.stderr}"

    def test_compile_fibonacci_c(self, samples_dir: Path, temp_output_dir: Path):
        from r2b.compilation.compiler import compile_c_source
        
        fib_c = samples_dir / "fibonacci.c"
        if not fib_c.exists():
            pytest.skip("fibonacci.c not found")
        
        result = compile_c_source(
            source=fib_c,
            architecture="arm64",
            output=temp_output_dir / "fibonacci",
        )
        
        assert result.success, f"Failed to compile fibonacci.c: {result.stderr}"

    def test_compile_all_samples_arm64(self, samples_dir: Path, temp_output_dir: Path):
        from r2b.compilation.compiler import compile_c_source
        
        FREESTANDING_FILES = {"syscalls.c"}
        
        c_files = list(samples_dir.glob("*.c"))
        assert len(c_files) > 0, "No C files found in samples/c"
        
        failed = []
        for c_file in c_files:
            output = temp_output_dir / c_file.stem
            
            extra_flags = None
            if c_file.name in FREESTANDING_FILES:
                extra_flags = ["-ffreestanding", "-nostartfiles", "-nodefaultlibs", "-static"]
            
            result = compile_c_source(
                source=c_file,
                architecture="arm64",
                output=output,
                extra_flags=extra_flags,
            )
            
            if not result.success:
                failed.append((c_file.name, result.stderr))
        
        if failed:
            failure_msg = "\n".join(f"  {name}: {err[:100]}" for name, err in failed)
            pytest.fail(f"Failed to compile:\n{failure_msg}")
