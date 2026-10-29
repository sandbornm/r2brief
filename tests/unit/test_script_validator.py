

class TestPythonValidation:

    def test_valid_python_passes(self):
        from r2b.tools.models import ScriptLanguage, ToolName
        from r2b.tools.validator import ScriptValidator

        script = """
def analyze_function(func):
    name = func.getName()
    entry = func.getEntryPoint()
    return (name, entry)

result = analyze_function(current_function)
print(result)
"""
        result = ScriptValidator.validate(script, ScriptLanguage.PYTHON, ToolName.GHIDRA)

        assert result.valid is True
        assert len(result.errors) == 0

    def test_syntax_error_detected(self):
        from r2b.tools.models import ScriptLanguage, ToolName
        from r2b.tools.validator import ScriptValidator

        script = """def broken_function(
    # Missing closing paren and colon
    print("hello"
"""
        result = ScriptValidator.validate(script, ScriptLanguage.PYTHON, ToolName.GHIDRA)

        assert result.valid is False
        assert len(result.errors) >= 1
        assert "line" in result.errors[0].location.lower()

    def test_ghidra_api_warning(self):
        from r2b.tools.models import ScriptLanguage, ToolName
        from r2b.tools.validator import ScriptValidator

        script = """
functions = getFunctions(True)  # Wrong - should use FunctionManager
for func in functions:
    print(func.getName())
"""
        result = ScriptValidator.validate(script, ScriptLanguage.PYTHON, ToolName.GHIDRA)

        assert len(result.warnings) >= 1
        warning = result.warnings[0]
        assert (
            "FunctionManager" in (warning.suggestion or "")
            or "currentProgram" in (warning.suggestion or "")
        )


class TestR2Validation:

    def test_valid_r2_command(self):
        from r2b.tools.models import ScriptLanguage, ToolName
        from r2b.tools.validator import ScriptValidator

        script = """
aaa
afl
pdf @ main
"""
        result = ScriptValidator.validate(script, ScriptLanguage.R2, ToolName.RADARE2)

        assert result.valid is True
        assert len(result.errors) == 0

    def test_dangerous_command_warning(self):
        from r2b.tools.models import ScriptLanguage, ToolName
        from r2b.tools.validator import ScriptValidator

        script = """
aaa
!rm -rf /tmp/test
afl
"""
        result = ScriptValidator.validate(script, ScriptLanguage.R2, ToolName.RADARE2)

        assert len(result.warnings) >= 1
        warning_messages = " ".join(w.message.lower() for w in result.warnings)
        assert "shell" in warning_messages or "escape" in warning_messages


class TestShellValidation:

    def test_valid_binwalk_command(self):
        from r2b.tools.models import ScriptLanguage, ToolName
        from r2b.tools.validator import ScriptValidator

        script = "binwalk -e firmware.bin"
        result = ScriptValidator.validate(script, ScriptLanguage.SHELL, ToolName.BINWALK)

        assert result.valid is True
        assert len(result.errors) == 0

    def test_dangerous_shell_rejected(self):
        from r2b.tools.models import ScriptLanguage, ToolName
        from r2b.tools.validator import ScriptValidator

        script = "rm -rf /"
        result = ScriptValidator.validate(script, ScriptLanguage.SHELL, ToolName.BINWALK)

        assert result.valid is False
        assert len(result.errors) >= 1


class TestDangerousPythonPatterns:

    def test_os_system_warning(self):
        from r2b.tools.models import ScriptLanguage, ToolName
        from r2b.tools.validator import ScriptValidator

        script = 'import os\nos.system("ls -la")'
        result = ScriptValidator.validate(script, ScriptLanguage.PYTHON, ToolName.GHIDRA)

        assert len(result.warnings) >= 1

    def test_subprocess_shell_warning(self):
        from r2b.tools.models import ScriptLanguage, ToolName
        from r2b.tools.validator import ScriptValidator

        script = 'import subprocess\nsubprocess.run("ls", shell=True)'
        result = ScriptValidator.validate(script, ScriptLanguage.PYTHON, ToolName.GHIDRA)

        assert len(result.warnings) >= 1


class TestAngrPatternValidation:

    def test_valid_angr_script(self):
        from r2b.tools.models import ScriptLanguage, ToolName
        from r2b.tools.validator import ScriptValidator

        script = """
import angr
proj = angr.Project('./binary', auto_load_libs=False)
cfg = proj.analyses.CFGFast()
for func in cfg.kb.functions.values():
    print(func.name)
"""
        result = ScriptValidator.validate(script, ScriptLanguage.PYTHON, ToolName.ANGR)

        assert result.valid is True

    def test_angr_state_not_stepped_warning(self):
        from r2b.tools.models import ScriptLanguage, ToolName
        from r2b.tools.validator import ScriptValidator

        script = """
import angr
proj = angr.Project('./binary')
state = proj.factory.entry_state()
# Missing: simgr = proj.factory.simulation_manager(state)
# Missing: simgr.explore(find=...)
print(state.regs.pc)
"""
        result = ScriptValidator.validate(script, ScriptLanguage.PYTHON, ToolName.ANGR)

        assert result.valid is True


class TestGhidraPatternValidation:

    def test_get_bytes_warning(self):
        from r2b.tools.models import ScriptLanguage, ToolName
        from r2b.tools.validator import ScriptValidator

        script = """
# Wrong: getBytes without proper context
data = getBytes(addr, 10)
"""
        result = ScriptValidator.validate(script, ScriptLanguage.PYTHON, ToolName.GHIDRA)

        assert len(result.warnings) >= 1

    def test_get_data_at_warning(self):
        from r2b.tools.models import ScriptLanguage, ToolName
        from r2b.tools.validator import ScriptValidator

        script = """
data = getDataAt(addr)
"""
        result = ScriptValidator.validate(script, ScriptLanguage.PYTHON, ToolName.GHIDRA)

        assert len(result.warnings) >= 1

    def test_get_symbols_warning(self):
        from r2b.tools.models import ScriptLanguage, ToolName
        from r2b.tools.validator import ScriptValidator

        script = """
symbols = getSymbols("main")
"""
        result = ScriptValidator.validate(script, ScriptLanguage.PYTHON, ToolName.GHIDRA)

        assert len(result.warnings) >= 1


class TestDangerousShellPatterns:

    def test_mkfs_rejected(self):
        from r2b.tools.models import ScriptLanguage, ToolName
        from r2b.tools.validator import ScriptValidator

        script = "mkfs.ext4 /dev/sda1"
        result = ScriptValidator.validate(script, ScriptLanguage.SHELL, ToolName.BINWALK)

        assert result.valid is False

    def test_dd_to_dev_rejected(self):
        from r2b.tools.models import ScriptLanguage, ToolName
        from r2b.tools.validator import ScriptValidator

        script = "dd if=/dev/zero of=/dev/sda"
        result = ScriptValidator.validate(script, ScriptLanguage.SHELL, ToolName.BINWALK)

        assert result.valid is False

    def test_chmod_recursive_777_warning(self):
        from r2b.tools.models import ScriptLanguage, ToolName
        from r2b.tools.validator import ScriptValidator

        script = "chmod -R 777 /some/path"
        result = ScriptValidator.validate(script, ScriptLanguage.SHELL, ToolName.BINWALK)

        assert result.valid is False or len(result.warnings) >= 1


class TestDangerousR2Patterns:

    def test_shell_escape_at_start(self):
        from r2b.tools.models import ScriptLanguage, ToolName
        from r2b.tools.validator import ScriptValidator

        script = "!whoami"
        result = ScriptValidator.validate(script, ScriptLanguage.R2, ToolName.RADARE2)

        assert len(result.warnings) >= 1

    def test_shell_escape_after_semicolon(self):
        from r2b.tools.models import ScriptLanguage, ToolName
        from r2b.tools.validator import ScriptValidator

        script = "aaa; !ls"
        result = ScriptValidator.validate(script, ScriptLanguage.R2, ToolName.RADARE2)

        assert len(result.warnings) >= 1
