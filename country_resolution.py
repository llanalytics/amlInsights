from __future__ import annotations

import csv
import json
from functools import lru_cache
from pathlib import Path
from typing import Iterable


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "country_aliases.json"

_FALLBACK_ALIASES: dict[str, str] = {
    "france": "FR",
    "french republic": "FR",
    "russia": "RU",
    "russian federation": "RU",
    "united states": "US",
    "usa": "US",
    "us": "US",
    "u.s.": "US",
    "united kingdom": "GB",
    "uk": "GB",
    "u.k.": "GB",
}


def _normalize_alias(value: object) -> str:
    return " ".join(str(value or "").strip().lower().split())


def _resolve_config_path(path: object, *, base_dir: Path) -> Path | None:
    raw = str(path or "").strip()
    if not raw:
        return None
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = base_dir / candidate
    return candidate.resolve()


def _load_config(config_path: Path) -> dict[str, object]:
    if not config_path.exists():
        return {}
    with config_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, dict) else {}


def _load_country_dimension_aliases(paths: Iterable[Path]) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for path in paths:
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                code2 = str(row.get("country_code_2") or "").strip().upper()
                code3 = str(row.get("country_code_3") or "").strip().upper()
                name = _normalize_alias(row.get("country_name"))
                if not code2:
                    continue
                if name:
                    aliases[name] = code2
                if code2:
                    aliases[code2.lower()] = code2
                if code3:
                    aliases[code3.lower()] = code2
    return aliases


@lru_cache(maxsize=1)
def country_aliases_to_code_2() -> dict[str, str]:
    config = _load_config(DEFAULT_CONFIG_PATH)
    base_dir = DEFAULT_CONFIG_PATH.parent
    configured_paths = config.get("country_dimension_paths") if isinstance(config.get("country_dimension_paths"), list) else []
    dimension_paths = [
        path
        for path in (_resolve_config_path(value, base_dir=base_dir) for value in configured_paths)
        if path is not None
    ]
    aliases = _load_country_dimension_aliases(dimension_paths)
    aliases.update(_FALLBACK_ALIASES)

    configured_aliases = config.get("aliases") if isinstance(config.get("aliases"), dict) else {}
    for alias, code in configured_aliases.items():
        normalized_alias = _normalize_alias(alias)
        normalized_code = str(code or "").strip().upper()
        if normalized_alias and normalized_code:
            aliases[normalized_alias] = normalized_code

    return aliases


def iter_country_aliases() -> list[tuple[str, str]]:
    aliases = country_aliases_to_code_2()
    return sorted(aliases.items(), key=lambda item: (-len(item[0]), item[0]))
