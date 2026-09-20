from io import BytesIO
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request

import pytest

from telegent import EndpointProbe, ProbeSettings, TelegentError
from telegent.cli import main
from telegent.probe.client import _NoRedirect, probe_endpoint
from telegent.probe.config import ProbeTarget


def _configuration(root: Path) -> Path:
    model_dir = root / "deepseek"
    model_dir.mkdir(parents=True)
    (model_dir / "config.toml").write_text(
        '[model_providers.official]\nbase_url = "https://api.example.test/v1"\n'
        'wire_api = "responses"\nenv_key = "OFFICIAL_KEY"\n'
        '[model_providers.openrouter]\nbase_url = "https://router.example.test/api/v1/"\n'
        'wire_api = "responses"\nenv_key = "ROUTER_KEY"\n',
        encoding="utf-8",
    )
    (model_dir / "official.config.toml").write_text(
        'model_provider = "official"\nmodel = "deepseek-official"\n',
        encoding="utf-8",
    )
    (model_dir / "openrouter.config.toml").write_text(
        'model_provider = "openrouter"\nmodel = "deepseek/router"\n',
        encoding="utf-8",
    )
    return model_dir


def test_probe_settings_precedence_and_no_example_fallback(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "TELEGENT_CODEX_CONFIG_ROOT=dotenv-config\n"
        "TELEGENT_TEST_TIMEOUT_SECONDS=20\n"
        "ROUTER_KEY=dotenv-secret\n",
        encoding="utf-8",
    )
    settings = ProbeSettings.resolve(
        {"codex_config_root": "cli-config", "timeout_seconds": 5},
        environ={"TELEGENT_CODEX_CONFIG_ROOT": "process-config", "ROUTER_KEY": "process-secret"},
        cwd=tmp_path,
    )
    assert settings.codex_config_root == tmp_path / "cli-config"
    assert settings.timeout_seconds == 5
    assert settings.environment["ROUTER_KEY"] == "process-secret"
    assert settings.env_file == env_file

    env_file.unlink()
    (tmp_path / ".env.example").write_text(
        "TELEGENT_CODEX_CONFIG_ROOT=example-config\n", encoding="utf-8"
    )
    defaults = ProbeSettings.resolve(environ={}, cwd=tmp_path)
    assert defaults.codex_config_root == tmp_path / "codex-third-party"
    assert defaults.env_file is None


def test_endpoint_probe_resolves_every_model_and_continues_after_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configuration(tmp_path)
    settings = ProbeSettings.resolve(
        {"codex_config_root": tmp_path},
        environ={"OFFICIAL_KEY": "secret-1", "ROUTER_KEY": "secret-2"},
        cwd=tmp_path,
    )
    calls: list[tuple[str, str, str, float]] = []

    def fake_probe(target: ProbeTarget, timeout: float) -> tuple[bool, str]:
        calls.append((target.provider, target.model_id, target.url, timeout))
        return target.provider == "openrouter", "completed" if target.provider == "openrouter" else "HTTP 401"

    monkeypatch.setattr("telegent.probe.runner.probe_endpoint", fake_probe)
    results = EndpointProbe(settings).run("deepseek")

    assert [result.status for result in results] == ["FAIL", "PASS"]
    assert calls == [
        ("official", "deepseek-official", "https://api.example.test/v1/responses", 60),
        ("openrouter", "deepseek/router", "https://router.example.test/api/v1/responses", 60),
    ]
    assert "secret" not in repr(results)


def test_missing_key_is_skipped_without_stopping_other_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configuration(tmp_path)
    settings = ProbeSettings.resolve(
        {"codex_config_root": tmp_path},
        environ={"ROUTER_KEY": "secret"},
        cwd=tmp_path,
    )
    calls: list[str] = []

    def fake_probe(target: ProbeTarget, timeout: float) -> tuple[bool, str]:
        calls.append(target.provider)
        return True, "completed"

    monkeypatch.setattr("telegent.probe.runner.probe_endpoint", fake_probe)
    results = EndpointProbe(settings).run("deepseek")

    assert [result.status for result in results] == ["SKIP", "PASS"]
    assert calls == ["openrouter"]


def test_missing_profile_and_unsupported_wire_api_are_reported_per_provider(
    tmp_path: Path
) -> None:
    model_dir = _configuration(tmp_path)
    (model_dir / "official.config.toml").unlink()
    config = model_dir / "config.toml"
    config.write_text(config.read_text(encoding="utf-8").replace(
        'wire_api = "responses"', 'wire_api = "chat"', 1
    ), encoding="utf-8")
    settings = ProbeSettings.resolve(
        {"codex_config_root": tmp_path},
        environ={"OFFICIAL_KEY": "secret", "ROUTER_KEY": "secret"},
        cwd=tmp_path,
    )
    results = EndpointProbe(settings).run("deepseek", dry_run=True)
    assert [result.status for result in results] == ["FAIL", "READY"]
    assert "configuration does not exist" in results[0].detail

    (model_dir / "official.config.toml").write_text(
        'model_provider = "official"\nmodel = "model"\n', encoding="utf-8"
    )
    results = EndpointProbe(settings).run("deepseek", dry_run=True)
    assert [result.status for result in results] == ["FAIL", "READY"]
    assert "responses wire API" in results[0].detail


def test_invalid_endpoint_url_fails_without_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    model_dir = _configuration(tmp_path)
    config = model_dir / "config.toml"
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            "https://api.example.test/v1", "http://remote.example.test/v1"
        ),
        encoding="utf-8",
    )
    settings = ProbeSettings.resolve(
        {"codex_config_root": tmp_path},
        environ={"OFFICIAL_KEY": "secret", "ROUTER_KEY": "secret"},
        cwd=tmp_path,
    )
    monkeypatch.setattr(
        "telegent.probe.runner.probe_endpoint",
        lambda *_: (True, "completed"),
    )
    results = EndpointProbe(settings).run("deepseek")
    assert [result.status for result in results] == ["FAIL", "PASS"]
    assert "invalid or insecure base_url" in results[0].detail


def test_probe_client_sends_minimal_request_and_rejects_incomplete_response(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    target = ProbeTarget("official", "model-id", "https://api.example.test/v1/responses", "KEY", "secret")
    requests: list[Request] = []

    class FakeResponse:
        def __init__(self, payload: bytes):
            self.payload = payload

        def __enter__(self) -> "FakeResponse":
            return self

        def __exit__(self, *_: object) -> None:
            pass

        def read(self, size: int) -> bytes:
            assert size == 262145
            return self.payload

    class FakeOpener:
        def __init__(self, payload: bytes):
            self.payload = payload

        def open(self, request: Request, timeout: float) -> FakeResponse:
            assert timeout == 10
            requests.append(request)
            return FakeResponse(self.payload)

    opener = FakeOpener(b'{"status":"completed"}')
    monkeypatch.setattr("telegent.probe.client.build_opener", lambda handler: opener)
    assert probe_endpoint(target, 10) == (True, "completed")
    assert requests[0].full_url == target.url
    assert requests[0].get_method() == "POST"
    assert requests[0].get_header("Authorization") == "Bearer secret"
    assert b'"input": "Hi"' in requests[0].data
    assert b'"model": "model-id"' in requests[0].data
    assert b'"max_output_tokens": 4096' in requests[0].data

    opener.payload = (
        b'{"status":"incomplete","incomplete_details":{"reason":"max_output_tokens"},'
        b'"usage":{"output_tokens":4096,"output_tokens_details":{"reasoning_tokens":4096}}}'
    )
    assert probe_endpoint(target, 10) == (
        False,
        "status=incomplete; incomplete_reason=max_output_tokens; "
        "output_tokens=4096; reasoning_tokens=4096",
    )
    opener.payload = b'{"status":{"secret":"secret"},"error":{"message":"secret"}}'
    assert probe_endpoint(target, 10) == (False, "status=missing_or_unknown")
    assert _NoRedirect().redirect_request(requests[0], None, 302, "", {}, "https://elsewhere.test") is None


def test_probe_client_reports_http_and_network_errors_without_body_or_key(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    target = ProbeTarget("official", "model", "https://api.example.test/responses", "KEY", "secret")

    class FakeOpener:
        def __init__(self, error: Exception):
            self.error = error

        def open(self, request: Request, timeout: float) -> None:
            raise self.error

    opener = FakeOpener(
        HTTPError(
            target.url,
            401,
            "secret body",
            {},
            BytesIO(
                b'{"error":{"code":"invalid_api_key","type":"invalid_request_error",'
                b'"message":"secret body"}}'
            ),
        )
    )
    monkeypatch.setattr("telegent.probe.client.build_opener", lambda handler: opener)
    assert probe_endpoint(target, 10) == (
        False,
        "HTTP 401; status=missing_or_unknown; error_code=invalid_api_key; "
        "error_type=invalid_request_error",
    )
    opener.error = HTTPError(
        target.url,
        502,
        "secret",
        {},
        BytesIO(b'{"error":{"code":"secret","message":"secret"}}'),
    )
    assert probe_endpoint(target, 10) == (False, "HTTP 502; status=missing_or_unknown")
    opener.error = URLError("secret in low-level exception")
    assert probe_endpoint(target, 10) == (False, "connection error (URLError)")
    opener.error = TimeoutError("secret in timeout")
    assert probe_endpoint(target, 10) == (False, "connection error (TimeoutError)")


def test_test_cli_dry_run_and_exit_status(
    tmp_path: Path, capsys: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configuration(tmp_path / "configs")
    (tmp_path / ".env").write_text(
        "TELEGENT_CODEX_CONFIG_ROOT=configs\nOFFICIAL_KEY=secret\nROUTER_KEY=secret\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("TELEGENT_CODEX_CONFIG_ROOT", raising=False)
    monkeypatch.delenv("OFFICIAL_KEY", raising=False)
    monkeypatch.delenv("ROUTER_KEY", raising=False)

    def unexpected_request(*_: object) -> None:
        raise AssertionError("dry run sent an HTTP request")

    monkeypatch.setattr("telegent.probe.runner.probe_endpoint", unexpected_request)
    assert main(["test", "deepseek", "--provider", "openrouter", "--dry-run"]) == 0
    output = capsys.readouterr().out  # type: ignore[attr-defined]
    assert "READY openrouter: deepseek/router at https://router.example.test/api/v1/responses" in output
    assert "key: ROUTER_KEY" in output
    assert "secret" not in output

    monkeypatch.setattr("telegent.probe.runner.probe_endpoint", lambda *_: (False, "HTTP 401"))
    assert main(["test", "deepseek", "--provider", "openrouter"]) == 1
    assert "HTTP 401" in capsys.readouterr().out  # type: ignore[attr-defined]


def test_invalid_model_and_missing_explicit_env_file(tmp_path: Path) -> None:
    settings = ProbeSettings.resolve(environ={}, cwd=tmp_path)
    with pytest.raises(TelegentError, match="safe path component"):
        EndpointProbe(settings).run("../outside")
    with pytest.raises(TelegentError, match="environment file does not exist"):
        ProbeSettings.resolve({"env_file": tmp_path / "missing.env"}, environ={}, cwd=tmp_path)
