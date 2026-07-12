from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ADAPTER_DIR = Path(__file__).parent.parent / "adapters"
DEFAULT_ADAPTER_PATH = Path(__file__).parent / "default_adapter.json"


class AdapterError(ValueError):
    pass


def load_adapters() -> dict[str, dict[str, Any]]:
    # The builtin is independent of the mutable adapters directory, which is
    # commonly mounted as a volume in container deployments.
    adapters: dict[str, dict[str, Any]] = {"default": _builtin_default_adapter()}
    for path in sorted(ADAPTER_DIR.glob("*.json")):
        try:
            adapter = json.loads(path.read_text(encoding="utf-8"))
            adapter_id = adapter["id"]
            if not isinstance(adapter_id, str) or not adapter_id:
                raise AdapterError("id must be a non-empty string")
            if "search" not in adapter or "result" not in adapter:
                raise AdapterError("search and result sections are required")
            adapters[adapter_id] = adapter
        except (OSError, json.JSONDecodeError, KeyError, AdapterError) as error:
            if path.name == "default.json":
                # The bundled fallback remains usable and startup repairs this
                # editable copy on the next initialisation.
                continue
            raise AdapterError(f"Invalid adapter {path.name}: {error}") from error
    return adapters


def _builtin_default_adapter() -> dict[str, Any]:
    try:
        adapter = json.loads(DEFAULT_ADAPTER_PATH.read_text(encoding="utf-8"))
        validate_adapter(adapter)
        return adapter
    except (OSError, json.JSONDecodeError, AdapterError) as error:
        raise AdapterError(f"Bundled default adapter is invalid: {error}") from error


def ensure_default_adapter() -> None:
    """Restore the editable copy when a rebuild or empty volume removed it."""
    _builtin_default_adapter()
    path = ADAPTER_DIR / "default.json"
    if path.exists():
        try:
            adapter = json.loads(path.read_text(encoding="utf-8"))
            validate_adapter(adapter)
            if adapter.get("id") == "default":
                return
        except (OSError, json.JSONDecodeError, AdapterError):
            pass
    ADAPTER_DIR.mkdir(parents=True, exist_ok=True)
    path.write_text(DEFAULT_ADAPTER_PATH.read_text(encoding="utf-8"), encoding="utf-8")


def get_adapter(adapter_id: str) -> dict[str, Any]:
    try:
        return load_adapters()[adapter_id]
    except KeyError as error:
        raise AdapterError(f"Unknown adapter: {adapter_id}") from error


def public_adapters() -> list[dict[str, str]]:
    return [
        {"id": adapter_id, "label": str(adapter.get("label", adapter_id))}
        for adapter_id, adapter in load_adapters().items()
    ]


def get_adapter_definition(adapter_id: str) -> dict[str, Any]:
    return get_adapter(adapter_id)


def save_adapter(
    adapter: dict[str, Any], existing_id: str | None = None
) -> dict[str, Any]:
    validate_adapter(adapter)
    adapter_id = adapter["id"]
    if not adapter_id.replace("_", "").replace("-", "").isalnum():
        raise AdapterError(
            "Adapter id may contain only letters, numbers, hyphens, and underscores"
        )
    if existing_id is not None and adapter_id != existing_id:
        raise AdapterError("Adapter id cannot be changed while editing")
    path = ADAPTER_DIR / f"{adapter_id}.json"
    if existing_id is None and path.exists():
        raise AdapterError("An adapter with this id already exists")
    ADAPTER_DIR.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(adapter, indent=2) + "\n", encoding="utf-8")
    return adapter


def validate_adapter(adapter: dict[str, Any]) -> None:
    try:
        adapter_id = adapter["id"]
        if not isinstance(adapter_id, str) or not adapter_id:
            raise AdapterError("id must be a non-empty string")
        if not isinstance(adapter["label"], str) or not adapter["label"]:
            raise AdapterError("label must be a non-empty string")
        if not isinstance(adapter["search"]["path_template"], str):
            raise AdapterError("search.path_template must be a string")
        if not isinstance(adapter["result"]["fields"], dict):
            raise AdapterError("result.fields must be an object")
    except KeyError as error:
        raise AdapterError(
            f"Missing required adapter property: {error.args[0]}"
        ) from error
