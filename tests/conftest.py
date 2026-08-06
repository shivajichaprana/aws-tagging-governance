"""Shared test fixtures for the tag-governance Lambda handlers.

Both handlers live in files named ``handler.py`` under different directories, so
they are loaded by path under distinct module names to avoid an import
collision. Each handler exposes a lazily-populated ``_CLIENTS`` dict; the
``reset_clients`` fixture clears it between tests so injected fakes never leak.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from types import ModuleType

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_REMEDIATOR = _REPO_ROOT / "lambda" / "tag-remediator" / "handler.py"
_DRIFT = _REPO_ROOT / "lambda" / "tag-drift-reporter" / "handler.py"


def _load(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"cannot load {name} from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def _dummy_aws_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """Never let a stray boto3 client reach real AWS during tests."""
    for var, value in {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_SESSION_TOKEN": "testing",
        "AWS_DEFAULT_REGION": "us-east-1",
    }.items():
        monkeypatch.setenv(var, value)


@pytest.fixture()
def remediator() -> ModuleType:
    return _load("tag_remediator_handler", _REMEDIATOR)


@pytest.fixture()
def drift_reporter() -> ModuleType:
    return _load("tag_drift_reporter_handler", _DRIFT)


@pytest.fixture()
def reset_clients(remediator: ModuleType, drift_reporter: ModuleType):
    """Clear cached boto3 clients before and after each test that uses fakes."""
    remediator._CLIENTS.clear()
    drift_reporter._CLIENTS.clear()
    yield
    remediator._CLIENTS.clear()
    drift_reporter._CLIENTS.clear()


@pytest.fixture()
def clear_tag_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove tag-governance env vars so each test controls its own config."""
    for var in (
        "DEFAULT_TAG_VALUES",
        "REQUIRED_TAG_KEYS",
        "EXCLUSION_TAG_KEYS",
        "SNS_TOPIC_ARN",
        "REPORT_BUCKET",
        "REPORT_PREFIX",
        "DRIFT_TAG_SCOPES",
        "RESOURCE_TYPE_FILTERS",
        "MAX_DRIFTED_IN_SUMMARY",
        "DRY_RUN",
        "ACCOUNT_ID",
        "PARTITION",
        "LOG_LEVEL",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AWS_REGION", "us-east-1")
