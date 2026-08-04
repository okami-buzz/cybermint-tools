"""
CyberMint Configuration System
"""
import json
import os
from pathlib import Path

DEFAULT_CONFIG = {
    "version": "1.0.0",
    "theme": "dark_cyan",
    "log_level": "INFO",
    "database": {
        "path": "database/cybermint.db"
    },
    "network": {
        "timeout": 10,
        "retries": 3
    },
    "recon": {
        "dns_timeout": 5,
        "whois_enabled": True
    },
    "reports": {
        "output_dir": "reports/",
        "default_format": "txt"
    },
    "plugins": {
        "directory": "plugins/",
        "auto_load": True
    },
    "updates": {
        "auto_check": True,
        "github_repo": "cybermint/cybermint"
    }
}

CONFIG_PATH = Path("database/config.json")


class Config:
    def __init__(self):
        self._config = {}
        self.load()

    def load(self):
        if CONFIG_PATH.exists():
            try:
                with open(CONFIG_PATH, "r") as f:
                    self._config = json.load(f)
            except Exception:
                self._config = DEFAULT_CONFIG.copy()
        else:
            self._config = DEFAULT_CONFIG.copy()
            self.save()

    def save(self):
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_PATH, "w") as f:
            json.dump(self._config, f, indent=2)

    def get(self, key, default=None):
        keys = key.split(".")
        val = self._config
        for k in keys:
            if isinstance(val, dict):
                val = val.get(k)
            else:
                return default
        return val if val is not None else default

    def set(self, key, value):
        keys = key.split(".")
        d = self._config
        for k in keys[:-1]:
            d = d.setdefault(k, {})
        d[keys[-1]] = value
        self.save()

    def get_all(self):
        return self._config.copy()

    def reset(self):
        self._config = DEFAULT_CONFIG.copy()
        self.save()


# Global config instance
config = Config()
