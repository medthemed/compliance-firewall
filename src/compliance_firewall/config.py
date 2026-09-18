"""Configuration loading for compliance-firewall.

Precedence (highest wins):

1. Explicit CLI flags
2. Environment variables (``CF_RULES_PATH``, ``CF_SEVERITY_THRESHOLD``)
3. Config file (``--config`` path, or auto-discovered ``cf.toml``)
4. Built-in defaults (empty)
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .models import Severity

# Well-known config filenames searched in the working directory.
CONFIG_FILENAMES = ("cf.toml", ".cf.toml", "compliance-firewall.toml")

ENV_RULES_PATH = "CF_RULES_PATH"
ENV_SEVERITY_THRESHOLD = "CF_SEVERITY_THRESHOLD"
ENV_CONFIG = "CF_CONFIG"

_SEVERITY_VALUES = {s.value: s for s in Severity}


class ConfigError(Exception):
    """Raised when a configuration file or value cannot be loaded."""


@dataclass(frozen=True)
class Config:
    """Resolved runtime configuration.

    Attributes:
        rules_path: Default rules file path, or None when unset.
        severity_threshold: Minimum severity for rules to participate, or None.
        sources: Human-readable labels describing where each value came from
            (useful for debugging precedence).
    """

    rules_path: Path | None = None
    severity_threshold: Severity | None = None
    sources: tuple[str, ...] = ()

    def merged_with(
        self,
        *,
        rules_path: Path | str | None = None,
        severity_threshold: Severity | str | None = None,
        source: str = "override",
    ) -> Config:
        """Return a copy with explicit values applied on top of this config."""
        new_rules = Path(rules_path) if rules_path is not None else self.rules_path
        new_sev: Severity | None
        if severity_threshold is None:
            new_sev = self.severity_threshold
        elif isinstance(severity_threshold, Severity):
            new_sev = severity_threshold
        else:
            new_sev = parse_severity(severity_threshold)

        extra: list[str] = []
        if rules_path is not None:
            extra.append(f"rules_path={source}")
        if severity_threshold is not None:
            extra.append(f"severity_threshold={source}")
        return Config(
            rules_path=new_rules,
            severity_threshold=new_sev,
            sources=self.sources + tuple(extra),
        )


def parse_severity(value: str) -> Severity:
    """Parse a severity name, raising ConfigError on unknown values."""
    normalized = value.strip().lower()
    if normalized not in _SEVERITY_VALUES:
        allowed = ", ".join(sorted(_SEVERITY_VALUES))
        raise ConfigError(
            f"Unknown severity {value!r}; expected one of: {allowed}"
        )
    return _SEVERITY_VALUES[normalized]


def discover_config_file(start: Path | None = None) -> Path | None:
    """Return the first well-known config file in ``start`` (default cwd)."""
    directory = Path(start) if start is not None else Path.cwd()
    for name in CONFIG_FILENAMES:
        candidate = directory / name
        if candidate.is_file():
            return candidate
    return None


def load_config_file(path: Path | str) -> Config:
    """Load a TOML config file into a Config."""
    path = Path(path)
    if not path.is_file():
        raise ConfigError(f"Config file not found: {path}")

    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"Invalid TOML in {path}: {exc}") from exc

    rules_path: Path | None = None
    severity: Severity | None = None
    sources: list[str] = [f"file:{path}"]

    if "rules_path" in data:
        raw = data["rules_path"]
        if not isinstance(raw, str) or not raw.strip():
            raise ConfigError(f"rules_path must be a non-empty string in {path}")
        rules_path = Path(raw)
        sources.append("rules_path=file")

    if "severity_threshold" in data:
        raw = data["severity_threshold"]
        if not isinstance(raw, str):
            raise ConfigError(
                f"severity_threshold must be a string in {path}"
            )
        severity = parse_severity(raw)
        sources.append("severity_threshold=file")

    unknown = set(data) - {"rules_path", "severity_threshold"}
    if unknown:
        # Tolerate unknown keys for forward compatibility; do not fail.
        pass

    return Config(
        rules_path=rules_path,
        severity_threshold=severity,
        sources=tuple(sources),
    )


def load_config(
    config_path: Path | str | None = None,
    *,
    use_env: bool = True,
    discover: bool = True,
    cwd: Path | None = None,
) -> Config:
    """Resolve configuration from file, environment, and defaults.

    Args:
        config_path: Explicit config file path. When provided it must exist.
        use_env: Read CF_* environment variables.
        discover: Search cwd for well-known config filenames when
            ``config_path`` is not given.
        cwd: Directory used for auto-discovery (defaults to Path.cwd()).

    Returns:
        A Config with the highest-precedence values applied.
    """
    sources: list[str] = []
    rules_path: Path | None = None
    severity: Severity | None = None

    # 1. Config file
    path: Path | None
    explicit = config_path is not None
    if explicit:
        path = Path(config_path)
    elif use_env and os.environ.get(ENV_CONFIG):
        path = Path(os.environ[ENV_CONFIG])
        explicit = True
    elif discover:
        path = discover_config_file(cwd)
    else:
        path = None

    if path is not None:
        file_cfg = load_config_file(path)
        rules_path = file_cfg.rules_path
        severity = file_cfg.severity_threshold
        sources.extend(file_cfg.sources)
    elif explicit:
        # config_path was set but load_config_file would have raised already
        # when the file is missing; this branch is defensive.
        raise ConfigError(f"Config file not found: {path}")

    # 2. Environment variables override the file
    if use_env:
        env_rules = os.environ.get(ENV_RULES_PATH, "").strip()
        if env_rules:
            rules_path = Path(env_rules)
            sources.append("rules_path=env")

        env_sev = os.environ.get(ENV_SEVERITY_THRESHOLD, "").strip()
        if env_sev:
            severity = parse_severity(env_sev)
            sources.append("severity_threshold=env")

    return Config(
        rules_path=rules_path,
        severity_threshold=severity,
        sources=tuple(sources),
    )


def filter_rules_by_severity(
    rules: list, threshold: Severity | None
) -> list:
    """Drop rules whose severity is below ``threshold``.

    When ``threshold`` is None the list is returned unchanged (as a new list).
    """
    if threshold is None:
        return list(rules)
    order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    min_idx = order.index(threshold)
    return [r for r in rules if order.index(r.severity) >= min_idx]
