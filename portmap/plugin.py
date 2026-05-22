"""Plugin system for portmap — load and execute custom labelling/enrichment plugins."""

from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path
from typing import Callable, List, Optional

from portmap.scanner import PortEntry

# Type alias for a plugin hook: receives a list of entries, returns enriched list
PluginHook = Callable[[List[PortEntry]], List[PortEntry]]

_registry: dict[str, PluginHook] = {}


def register(name: str, hook: PluginHook) -> None:
    """Register a plugin hook under *name*."""
    if not callable(hook):
        raise TypeError(f"Plugin hook must be callable, got {type(hook)}")
    _registry[name] = hook


def unregister(name: str) -> None:
    """Remove a previously registered plugin."""
    _registry.pop(name, None)


def list_plugins() -> List[str]:
    """Return names of all registered plugins."""
    return list(_registry.keys())


def apply(entries: List[PortEntry], plugin_name: Optional[str] = None) -> List[PortEntry]:
    """Apply one or all registered plugins to *entries*.

    If *plugin_name* is given only that plugin is applied; otherwise all
    registered plugins are applied in registration order.
    """
    if plugin_name is not None:
        hook = _registry.get(plugin_name)
        if hook is None:
            raise KeyError(f"No plugin registered as {plugin_name!r}")
        return hook(entries)

    result = list(entries)
    for hook in _registry.values():
        result = hook(result)
    return result


def load_from_path(path: str | Path) -> str:
    """Dynamically load a Python file as a plugin module.

    The module must call ``portmap.plugin.register(name, hook)`` at import
    time.  Returns the module name that was loaded.
    """
    path = Path(path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Plugin file not found: {path}")

    module_name = f"_portmap_plugin_{path.stem}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load plugin from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module_name


def clear() -> None:
    """Remove all registered plugins (mainly useful in tests)."""
    _registry.clear()
