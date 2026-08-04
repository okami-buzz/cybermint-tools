"""
CyberMint Core Engine
Brain of the CyberMint platform — manages modules, plugins, and lifecycle.
"""
import importlib
import os
import sys
from pathlib import Path

from core.config import config
from core.database import init_database
from core.logger import get_logger

logger = get_logger("Engine")


class CyberMintEngine:
    VERSION = "1.0.0"

    def __init__(self):
        self.modules = {}
        self.plugins = {}
        self._initialized = False

    def initialize(self):
        """Bootstrap the engine: DB, directories, modules, plugins."""
        self._ensure_directories()
        init_database()
        self._load_modules()
        if config.get("plugins.auto_load"):
            self._load_plugins()
        self._initialized = True
        logger.info("CyberMint Engine initialized — v%s", self.VERSION)

    # ── Directory Setup ───────────────────────────────────────────────────────

    def _ensure_directories(self):
        dirs = [
            "database", "database/logs",
            "plugins/custom_module",
            "plugins/community_module",
            "plugins/research_module",
            "reports",
            "themes",
            "docs",
        ]
        for d in dirs:
            Path(d).mkdir(parents=True, exist_ok=True)

    # ── Module Loading ────────────────────────────────────────────────────────

    def _load_modules(self):
        module_map = {
            "intelligence": "modules.intelligence.intelligence",
            "recon":        "modules.recon.recon",
            "analysis":     "modules.analysis.analysis",
            "network":      "modules.network.network",
            "forensics":    "modules.forensics.forensics",
            "threat":       "modules.threat.threat",
            "reports":      "modules.reports.reports",
        }
        for name, path in module_map.items():
            try:
                mod = importlib.import_module(path)
                self.modules[name] = mod
                logger.info("Loaded module: %s", name)
            except ImportError as e:
                logger.warning("Could not load module %s: %s", name, e)

    # ── Plugin Loading ────────────────────────────────────────────────────────

    def _load_plugins(self):
        plugin_dir = Path(config.get("plugins.directory", "plugins/"))
        if not plugin_dir.exists():
            return
        sys.path.insert(0, str(plugin_dir))
        for item in plugin_dir.iterdir():
            if item.is_dir() and (item / "__init__.py").exists():
                try:
                    plugin = importlib.import_module(item.name)
                    self.plugins[item.name] = plugin
                    logger.info("Loaded plugin: %s", item.name)
                except ImportError as e:
                    logger.warning("Could not load plugin %s: %s", item.name, e)

    # ── Public API ────────────────────────────────────────────────────────────

    def get_module(self, name):
        return self.modules.get(name)

    def list_modules(self):
        return list(self.modules.keys())

    def list_plugins(self):
        return list(self.plugins.keys())

    def get_version(self):
        return self.VERSION

    def health_check(self):
        return {
            "version": self.VERSION,
            "modules_loaded": len(self.modules),
            "plugins_loaded": len(self.plugins),
            "database": "ok",
            "status": "operational",
        }


# Global engine instance
engine = CyberMintEngine()
