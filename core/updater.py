"""
CyberMint Update System
"""
import requests
from core.config import config
from core.logger import get_logger
from core.engine import CyberMintEngine

logger = get_logger("Updater")

GITHUB_API = "https://api.github.com/repos/{repo}/releases/latest"


def check_for_updates():
    repo = config.get("updates.github_repo", "cybermint/cybermint")
    url = GITHUB_API.format(repo=repo)
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            latest = data.get("tag_name", "").lstrip("v")
            current = CyberMintEngine.VERSION
            if latest and latest != current:
                return {
                    "update_available": True,
                    "current": current,
                    "latest": latest,
                    "url": data.get("html_url", ""),
                    "notes": data.get("body", "")[:300],
                }
            return {"update_available": False, "current": current, "latest": latest}
        return {"update_available": False, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        logger.warning("Update check failed: %s", e)
        return {"update_available": False, "error": str(e)}
