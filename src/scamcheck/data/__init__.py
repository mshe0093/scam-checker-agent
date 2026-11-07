"""Curated datasets bundled with the package."""

from __future__ import annotations

import json
from functools import cache
from importlib import resources
from typing import Any


@cache
def load(name: str) -> dict[str, Any]:
    text = resources.files(__package__).joinpath(f"{name}.json").read_text(encoding="utf-8")
    return json.loads(text)


def orgs() -> list[dict[str, Any]]:
    return load("official_orgs")["orgs"]


def generic_reporting() -> list[dict[str, Any]]:
    return load("official_orgs")["generic_reporting"]


def patterns() -> list[dict[str, Any]]:
    return load("scam_patterns")["patterns"]


def reported_numbers() -> list[dict[str, Any]]:
    return load("reported_numbers")["numbers"]


def rules() -> dict[str, Any]:
    return load("rules")
