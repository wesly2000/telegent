"""Run configured provider probes and retain per-provider outcomes."""

from dataclasses import dataclass
from time import perf_counter
from typing import Literal

from ..errors import TelegentError
from .client import probe_endpoint
from .config import MissingCredential, configured_providers, load_target
from .settings import ProbeSettings


@dataclass(frozen=True)
class ProbeResult:
    provider: str
    status: Literal["PASS", "FAIL", "SKIP", "READY"]
    detail: str
    elapsed_ms: float | None = None


class EndpointProbe:
    """Test each configured provider with a minimal direct HTTP request."""

    def __init__(self, settings: ProbeSettings) -> None:
        self.settings = settings

    def run(
        self, model: str, provider: str | None = None, *, dry_run: bool = False
    ) -> list[ProbeResult]:
        providers = configured_providers(self.settings, model)
        if provider is not None:
            if provider not in providers:
                raise TelegentError(f"provider {provider!r} is not configured for {model!r}")
            names = [provider]
        else:
            names = sorted(providers)

        results = []
        for name in names:
            try:
                target = load_target(self.settings, model, name, providers[name])
            except MissingCredential as error:
                results.append(ProbeResult(name, "SKIP", str(error)))
                continue
            except TelegentError as error:
                results.append(ProbeResult(name, "FAIL", str(error)))
                continue
            detail = (
                f"{target.model_id} at {target.url} "
                f"(key: {target.key_environment_variable})"
            )
            if dry_run:
                results.append(ProbeResult(name, "READY", detail))
                continue
            started = perf_counter()
            passed, reason = probe_endpoint(target, self.settings.timeout_seconds)
            results.append(
                ProbeResult(
                    name,
                    "PASS" if passed else "FAIL",
                    f"{detail}; {reason}",
                    (perf_counter() - started) * 1000,
                )
            )
        return results
