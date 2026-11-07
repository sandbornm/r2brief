import pytest
from unittest.mock import MagicMock, patch


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("R2B_WEB_EXECUTION_TOKEN", "test-execution-token")
    with patch('r2b.web.app.build_state') as mock_build:
        mock_state = MagicMock()
        mock_state.chat_dao = MagicMock()
        mock_state.config.ghidra.use_bridge = False
        mock_state.config.web.enable_script_execution = True
        mock_state.config.web.execution_token_env = "R2B_WEB_EXECUTION_TOKEN"
        mock_state.env.ghidra.bridge_connected = False
        mock_state.env.ghidra.is_ready = False
        mock_state.dao = None
        mock_state.db = None
        mock_build.return_value = mock_state

        from r2b.web.app import create_app
        app = create_app()
        app.config['TESTING'] = True
        with app.test_client() as client:
            client.environ_base["HTTP_AUTHORIZATION"] = "Bearer test-execution-token"
            yield client


class TestToolsExecuteEndpoint:

    def test_execute_requires_tool(self, client):
        response = client.post('/api/tools/execute', json={
            'script': 'print("hello")',
            'language': 'python',
        })
        assert response.status_code == 400
        assert 'tool' in response.get_json()['error'].lower()

    def test_execute_requires_script(self, client):
        response = client.post('/api/tools/execute', json={
            'tool': 'ghidra',
            'language': 'python',
        })
        assert response.status_code == 400
        assert 'script' in response.get_json()['error'].lower()

    def test_execute_validates_tool_name(self, client):
        response = client.post('/api/tools/execute', json={
            'tool': 'invalid_tool',
            'script': 'print("hello")',
            'language': 'python',
        })
        assert response.status_code == 400
        assert 'tool' in response.get_json()['error'].lower()

    def test_execute_validates_language(self, client):
        response = client.post('/api/tools/execute', json={
            'tool': 'ghidra',
            'script': 'print("hello")',
            'language': 'invalid_lang',
        })
        assert response.status_code == 400
        assert 'language' in response.get_json()['error'].lower()

    def test_execute_returns_validation_errors(self, client):
        response = client.post('/api/tools/execute', json={
            'tool': 'ghidra',
            'script': 'def broken(',
            'language': 'python',
        })
        data = response.get_json()
        assert response.status_code == 400
        assert 'validation' in data
        assert data['validation']['valid'] is False
        assert len(data['validation']['errors']) > 0

    def test_execute_ghidra_without_bridge_returns_error(self, client):
        response = client.post('/api/tools/execute', json={
            'tool': 'ghidra',
            'script': 'print("hello")',
            'language': 'python',
        })
        data = response.get_json()
        assert 'validation' in data
        assert data['validation']['valid'] is True
        assert 'error' in data
        assert 'ghidra' in data['error'].lower() or 'bridge' in data['error'].lower()

    def test_execute_radare2_without_r2pipe_returns_error(self, client):
        response = client.post('/api/tools/execute', json={
            'tool': 'radare2',
            'script': 'aaa',
            'language': 'r2',
        })
        data = response.get_json()
        assert 'validation' in data
        assert 'error' in data or (
            data.get('execution') and data['execution'].get('status') == 'error'
        )

    def test_execute_success_returns_output(self, client):
        with patch('r2b.web.app.build_state') as mock_build:
            mock_state = MagicMock()
            mock_state.chat_dao = MagicMock()
            mock_state.config.ghidra.use_bridge = True
            mock_state.config.web.enable_script_execution = True
            mock_state.config.web.execution_token_env = "R2B_WEB_EXECUTION_TOKEN"
            mock_state.env.ghidra.bridge_connected = True
            mock_state.ghidra_client = MagicMock()
            mock_state.ghidra_client.is_connected.return_value = True
            mock_state.ghidra_client.execute_script.return_value = {
                'output': 'Hello from Ghidra',
                'error': None,
            }
            mock_state.dao = None
            mock_state.db = None
            mock_build.return_value = mock_state

            from r2b.web.app import create_app
            app = create_app()
            app.config['TESTING'] = True

            with app.test_client() as test_client:
                test_client.environ_base["HTTP_AUTHORIZATION"] = "Bearer test-execution-token"
                response = test_client.post('/api/tools/execute', json={
                    'tool': 'ghidra',
                    'script': 'print("hello")',
                    'language': 'python',
                    'session_id': 'test-session',
                })

                assert response.status_code == 200
                data = response.get_json()
                assert data['validation']['valid'] is True
                assert data['execution']['status'] == 'success'
                assert 'Hello from Ghidra' in data['execution']['stdout']

    def test_execute_is_disabled_without_explicit_gate(self, monkeypatch):
        with patch('r2b.web.app.build_state') as mock_build:
            mock_state = MagicMock()
            mock_state.chat_dao = MagicMock()
            mock_state.config.web.enable_script_execution = False
            mock_state.dao = None
            mock_state.db = None
            mock_build.return_value = mock_state

            from r2b.web.app import create_app

            app = create_app()
            app.config['TESTING'] = True
            with app.test_client() as test_client:
                response = test_client.post('/api/tools/execute', json={
                    'tool': 'ghidra',
                    'script': 'print("hello")',
                    'language': 'python',
                })

        assert response.status_code == 403
        assert 'disabled' in response.get_json()['error']

    def test_execute_empty_script_returns_error(self, client):
        response = client.post('/api/tools/execute', json={
            'tool': 'ghidra',
            'script': '   ',
            'language': 'python',
        })
        assert response.status_code == 400
        assert 'script' in response.get_json()['error'].lower()

    def test_execute_unimplemented_tool_returns_error(self, client):
        response = client.post('/api/tools/execute', json={
            'tool': 'angr',
            'script': 'print("test")',
            'language': 'python',
        })
        data = response.get_json()
        assert 'validation' in data
        assert data['validation']['valid'] is True
        assert 'error' in data
        assert 'not' in data['error'].lower() and 'implement' in data['error'].lower()


class TestToolsStatusEndpoint:

    def test_status_returns_all_tools(self, client):
        response = client.get('/api/tools/status')
        assert response.status_code == 200
        data = response.get_json()

        assert 'tools' in data
        tools = data['tools']
        assert 'ghidra' in tools
        assert 'radare2' in tools
        assert 'angr' in tools
        assert 'binwalk' in tools
        assert 'pyelftools' in tools
        assert 'pefile' in tools
        assert 'binwalk3' in tools
        assert 'unblob' in tools
        assert 'frida' in tools
        assert 'gef' in tools
        assert 'rizin' not in tools
        assert 'lief' not in tools
        assert 'keystone' not in tools
        assert 'pwntools' not in tools

    def test_status_tool_has_required_fields(self, client):
        response = client.get('/api/tools/status')
        data = response.get_json()

        for tool_name, tool_status in data['tools'].items():
            assert 'available' in tool_status, f"{tool_name} missing 'available'"
            assert 'description' in tool_status, f"{tool_name} missing 'description'"
            assert isinstance(tool_status['available'], bool)

    def test_status_ghidra_has_bridge_info(self, client):
        response = client.get('/api/tools/status')
        data = response.get_json()

        ghidra = data['tools']['ghidra']
        assert 'bridge_available' in ghidra
        assert 'bridge_connected' in ghidra
        assert 'headless_available' in ghidra

    def test_status_includes_summary(self, client):
        response = client.get('/api/tools/status')
        data = response.get_json()

        assert 'available_count' in data
        assert 'total_count' in data
        assert 'scorecard' in data
        assert 'score_summary' in data
        assert isinstance(data['available_count'], int)
        assert isinstance(data['total_count'], int)
        assert data['total_count'] >= data['available_count']
        assert 'radare2' in data['scorecard']
        assert {'state', 'quality', 'score', 'speed'} <= set(data['scorecard']['radare2'])


class TestCompilerCapabilitiesEndpoint:

    def test_compilers_returns_backward_compatible_fields(self, client):
        snapshot = {
            'state': 'ready',
            'generated_at': '2026-01-01T00:00:00+00:00',
            'compilers': {'arm32': [], 'arm64': [], 'x86': [], 'x86_64': []},
            'available_architectures': ['arm64'],
            'docker_available': True,
            'docker_image_exists': True,
            'architectures': {
                arch: {
                    'arch': arch,
                    'label': arch,
                    'state': 'ready' if arch == 'arm64' else 'missing',
                    'compilers': [],
                    'checked_candidates': [],
                    'operations': {
                        'compile_c': {'supported': arch == 'arm64', 'mode': 'docker', 'reason': 'test'},
                        'assemble': {'supported': False, 'mode': 'unavailable', 'reason': 'test'},
                    },
                }
                for arch in ('arm32', 'arm64', 'x86', 'x86_64')
            },
            'install_hints': [],
            'errors': [],
        }
        with patch('r2b.compilation.sniff_compiler_capabilities', return_value=snapshot):
            response = client.get('/api/compilers?live=1')
        assert response.status_code == 200
        data = response.get_json()

        assert 'state' in data
        assert 'compilers' in data
        assert 'available_architectures' in data
        assert 'docker_available' in data
        assert 'docker_image_exists' in data
        assert 'architectures' in data
        assert 'meta' in data
        for arch in ('arm32', 'arm64', 'x86', 'x86_64'):
            assert arch in data['compilers']
            assert arch in data['architectures']
            assert 'operations' in data['architectures'][arch]
            assert 'compile_c' in data['architectures'][arch]['operations']
            assert 'assemble' in data['architectures'][arch]['operations']

    def test_compile_preview_includes_support_diagnostics(self, client):
        preview = {
            'command': 'docker run r2b-compiler:latest aarch64-linux-gnu-gcc -o sample source.c',
            'uses_docker': True,
            'compiler': 'docker:aarch64-linux-gnu-gcc',
            'available': True,
            'reason': 'test',
            'requirements': ['r2b-compiler:latest'],
        }
        with patch('r2b.compilation.preview_compile_with_capabilities', return_value=preview):
            response = client.post('/api/compilers/preview', json={
                'architecture': 'arm64',
                'optimization': '-O0',
                'freestanding': True,
                'output_name': 'sample',
            })
        assert response.status_code == 200
        data = response.get_json()

        assert 'command' in data
        assert 'compiler' in data
        assert 'available' in data
        assert 'reason' in data
        assert 'requirements' in data
