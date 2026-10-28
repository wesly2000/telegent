import json
from pathlib import Path

import pytest

from telegent import EndpointProbe, ProbeSettings, TelegentError
from telegent.cli import main


def _executable(path: Path, body: str) -> Path:
    path.write_text(f"#!/usr/bin/python3\n{body}", encoding="utf-8")
    path.chmod(0o755)
    return path


def _codex_configuration(root: Path) -> Path:
    model_dir = root / "deepseek"
    model_dir.mkdir(parents=True)
    (model_dir / "config.toml").write_text(
        '[model_providers.official]\nenv_key = "OFFICIAL_KEY"\n'
        '[model_providers.openrouter]\nenv_key = "ROUTER_KEY"\n',
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
    (model_dir / "models.json").write_text("{}", encoding="utf-8")
    return model_dir


def _opencode_configuration(root: Path) -> Path:
    model_dir = root / "deepseek"
    model_dir.mkdir(parents=True)
    path = model_dir / "official.opencode.jsonc"
    path.write_text(
        """{
          model: "deepseek/deepseek-chat",
          provider: {
            deepseek: {
              npm: "@ai-sdk/openai-compatible",
              options: { apiKey: "{env:OFFICIAL_KEY}" },
            },
          },
        }
        """,
        encoding="utf-8",
    )
    return path


def _codex_binary(path: Path, *, failing_provider: str | None = None) -> Path:
    return _executable(
        path,
        "import json, os, pathlib, sys\n"
        "provider = sys.argv[sys.argv.index('-p') + 1]\n"
        "record = {\n"
        "  'args': sys.argv[1:],\n"
        "  'provider': provider,\n"
        "  'codex_home': os.environ['CODEX_HOME'],\n"
        "  'cwd': os.getcwd(),\n"
        "  'official_key': bool(os.environ.get('OFFICIAL_KEY')),\n"
        "  'router_key': bool(os.environ.get('ROUTER_KEY')),\n"
        "}\n"
        "with pathlib.Path(os.environ['PROBE_LOG']).open('a') as log:\n"
        "  log.write(json.dumps(record) + '\\n')\n"
        f"if provider == {failing_provider!r}: sys.exit(7)\n"
        "print(json.dumps({'type': 'thread.started', 'thread_id': 'thread-1'}))\n"
        "print(json.dumps({'type': 'item.completed', 'item': {"
        "'type': 'agent_message', 'text': 'secret response'}}))\n"
        "print(json.dumps({'type': 'turn.completed'}))\n",
    )


def test_probe_settings_precedence_and_no_example_fallback(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "TELEGENT_AGENT_CONFIG_ROOT=dotenv-config\n"
        "TELEGENT_TEST_TIMEOUT_SECONDS=20\n"
        "ROUTER_KEY=dotenv-secret\n",
        encoding="utf-8",
    )
    settings = ProbeSettings.resolve(
        {"agent_config_root": "cli-config", "timeout_seconds": 5},
        environ={
            "TELEGENT_AGENT_CONFIG_ROOT": "process-config",
            "ROUTER_KEY": "process-secret",
        },
        cwd=tmp_path,
    )
    assert settings.agent_config_root == tmp_path / "cli-config"
    assert settings.timeout_seconds == 5
    assert settings.environment["ROUTER_KEY"] == "process-secret"
    assert settings.env_file == env_file

    env_file.unlink()
    (tmp_path / ".env.example").write_text(
        "TELEGENT_AGENT_CONFIG_ROOT=example-config\n", encoding="utf-8"
    )
    defaults = ProbeSettings.resolve(environ={}, cwd=tmp_path)
    assert defaults.agent_config_root == tmp_path / "agent-config"
    assert defaults.env_file is None


def test_codex_probe_runs_every_provider_through_codex_and_continues_after_failure(
    tmp_path: Path,
) -> None:
    model_dir = _codex_configuration(tmp_path / "configs")
    log = tmp_path / "probe.jsonl"
    binary = _codex_binary(tmp_path / "codex", failing_provider="official")
    settings = ProbeSettings.resolve(
        {"agent_config_root": tmp_path / "configs", "agent_binary": binary},
        environ={
            "OFFICIAL_KEY": "secret-1",
            "ROUTER_KEY": "secret-2",
            "PROBE_LOG": str(log),
        },
        cwd=tmp_path,
    )

    results = EndpointProbe(settings).run("deepseek")

    assert [result.status for result in results] == ["FAIL", "PASS"]
    assert "status 7" in results[0].detail
    assert "minimal Codex prompt" in results[1].detail
    assert "secret" not in repr(results)
    records = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert [record["provider"] for record in records] == ["official", "openrouter"]
    assert all(record["codex_home"] == str(model_dir) for record in records)
    assert all(record["cwd"] == str(tmp_path) for record in records)
    assert records[0]["official_key"] and records[1]["router_key"]
    for record in records:
        assert record["args"][:4] == ["exec", "-p", record["provider"], "-c"]
        assert record["args"][4] == f'model_catalog_json="{model_dir / "models.json"}"'
        assert record["args"][-5:] == [
            "--json",
            "-s",
            "read-only",
            "--skip-git-repo-check",
            "Hi",
        ]


def test_codex_probe_reports_invalid_target_and_runs_later_provider(
    tmp_path: Path,
) -> None:
    model_dir = _codex_configuration(tmp_path / "configs")
    (model_dir / "official.config.toml").unlink()
    log = tmp_path / "probe.jsonl"
    binary = _codex_binary(tmp_path / "codex")
    settings = ProbeSettings.resolve(
        {"agent_config_root": tmp_path / "configs", "agent_binary": binary},
        environ={"ROUTER_KEY": "secret", "PROBE_LOG": str(log)},
        cwd=tmp_path,
    )

    results = EndpointProbe(settings).run("deepseek")

    assert [result.status for result in results] == ["FAIL", "PASS"]
    assert "provider profile does not exist" in results[0].detail
    records = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert [record["provider"] for record in records] == ["openrouter"]


def test_codex_probe_requires_a_completed_turn_and_text_response(tmp_path: Path) -> None:
    _codex_configuration(tmp_path / "configs")
    binary = _executable(
        tmp_path / "codex",
        "import json\nprint(json.dumps({'type': 'turn.completed'}))\n",
    )
    settings = ProbeSettings.resolve(
        {"agent_config_root": tmp_path / "configs", "agent_binary": binary},
        environ={"OFFICIAL_KEY": "secret", "ROUTER_KEY": "secret"},
        cwd=tmp_path,
    )

    results = EndpointProbe(settings).run("deepseek", "official")

    assert results[0].status == "FAIL"
    assert "did not emit a text response" in results[0].detail


def test_opencode_probe_runs_the_real_binary_in_an_isolated_environment(
    tmp_path: Path,
) -> None:
    config = _opencode_configuration(tmp_path / "configs")
    log = tmp_path / "probe.json"
    binary = _executable(
        tmp_path / "opencode",
        "import json, os, pathlib, sys\n"
        "names = ['XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME', "
        "'XDG_CACHE_HOME']\n"
        "record = {\n"
        "  'args': sys.argv[1:],\n"
        "  'config': json.loads(os.environ['OPENCODE_CONFIG_CONTENT']),\n"
        "  'xdg': [os.environ[name] for name in names],\n"
        "  'pure': os.environ.get('OPENCODE_PURE'),\n"
        "}\n"
        "pathlib.Path(os.environ['PROBE_LOG']).write_text(json.dumps(record))\n"
        "print(json.dumps({'type': 'text', 'part': {"
        "'type': 'text', 'text': 'secret response'}}))\n",
    )
    settings = ProbeSettings.resolve(
        {
            "agent": "opencode",
            "agent_config_root": tmp_path / "configs",
            "agent_binary": binary,
        },
        environ={"OFFICIAL_KEY": "secret", "PROBE_LOG": str(log)},
        cwd=tmp_path,
    )

    results = EndpointProbe(settings).run("deepseek")

    assert [result.status for result in results] == ["PASS"]
    assert "secret" not in repr(results)
    record = json.loads(log.read_text(encoding="utf-8"))
    assert record["args"] == [
        "run",
        "--format",
        "json",
        "--model",
        "deepseek/deepseek-chat",
        "--dir",
        str(tmp_path),
        "Hi",
    ]
    assert record["config"]["model"] == "deepseek/deepseek-chat"
    assert record["pure"] is None
    assert all(
        Path(path).parent.name.startswith("telegent-opencode-probe-")
        for path in record["xdg"]
    )
    assert all(not Path(path).exists() for path in record["xdg"])
    assert config.name == "official.opencode.jsonc"


def test_test_cli_dry_run_and_exit_status(
    tmp_path: Path, capsys: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    _codex_configuration(tmp_path / "configs")
    binary = _codex_binary(tmp_path / "codex")
    (tmp_path / ".env").write_text(
        "TELEGENT_AGENT_CONFIG_ROOT=configs\n"
        f"TELEGENT_AGENT_BINARY={binary}\n"
        "OFFICIAL_KEY=secret\n"
        "ROUTER_KEY=secret\n"
        f"PROBE_LOG={tmp_path / 'probe.jsonl'}\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    for name in (
        "TELEGENT_AGENT_CONFIG_ROOT",
        "TELEGENT_AGENT_BINARY",
        "OFFICIAL_KEY",
        "ROUTER_KEY",
        "PROBE_LOG",
    ):
        monkeypatch.delenv(name, raising=False)

    assert main(["test", "--agent", "codex", "deepseek", "--dry-run"]) == 0
    output = capsys.readouterr().out  # type: ignore[attr-defined]
    assert "READY official: deepseek-official via" in output
    assert "READY openrouter: deepseek/router via" in output
    assert "no agents started" in output
    assert "secret" not in output

    assert main(["test", "--agent", "codex", "deepseek"]) == 0
    output = capsys.readouterr().out  # type: ignore[attr-defined]
    assert "agent test complete: 2/2 passed" in output
    assert "secret response" not in output


@pytest.mark.parametrize(
    "arguments",
    (
        ["test", "model", "--dry-run"],
        ["test", "--agent", "codex", "model", "--codex-config-root", "x"],
    ),
)
def test_probe_agent_is_required_and_removed_codex_flags_are_rejected(
    arguments: list[str],
) -> None:
    with pytest.raises(SystemExit) as raised:
        main(arguments)
    assert raised.value.code == 2


def test_invalid_model_missing_env_file_and_unknown_provider(tmp_path: Path) -> None:
    _codex_configuration(tmp_path / "configs")
    settings = ProbeSettings.resolve(
        {"agent_config_root": tmp_path / "configs"},
        environ={"OFFICIAL_KEY": "secret", "ROUTER_KEY": "secret"},
        cwd=tmp_path,
    )
    with pytest.raises(TelegentError, match="safe path component"):
        EndpointProbe(settings).run("../outside")
    with pytest.raises(TelegentError, match="not configured"):
        EndpointProbe(settings).run("deepseek", "missing")
    with pytest.raises(TelegentError, match="environment file does not exist"):
        ProbeSettings.resolve(
            {"env_file": tmp_path / "missing.env"}, environ={}, cwd=tmp_path
        )


def test_unsupported_agent_has_no_probe_fallback(tmp_path: Path) -> None:
    settings = ProbeSettings.resolve(environ={}, cwd=tmp_path)
    object.__setattr__(settings, "agent", "unsupported")

    with pytest.raises(NotImplementedError, match="agent probing.*unsupported"):
        EndpointProbe(settings).run("model")
