from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

DATA_DIR = Path(os.getenv("WEBAPP_DATA_DIR", Path(__file__).resolve().parent / "data"))
RUNS_DIR = DATA_DIR / "runs"


def ensure_storage() -> None:
    RUNS_DIR.mkdir(parents=True, exist_ok=True)


def run_dir(run_id: str) -> Path:
    return RUNS_DIR / run_id


def run_reports_dir(run_id: str) -> Path:
    return run_dir(run_id) / "reports"


def run_log_path(run_id: str) -> Path:
    return run_dir(run_id) / "run.log"


def _atomic_write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp_path.replace(path)


def _read_json(path: Path) -> Optional[Any]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def save_meta(run_id: str, meta: Dict[str, Any]) -> None:
    ensure_storage()
    _atomic_write_json(run_dir(run_id) / "meta.json", meta)


def load_meta(run_id: str) -> Optional[Dict[str, Any]]:
    data = _read_json(run_dir(run_id) / "meta.json")
    if isinstance(data, dict):
        return data
    return None


def update_meta(run_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
    meta = load_meta(run_id) or {"id": run_id}
    meta.update(updates)
    save_meta(run_id, meta)
    return meta


def save_report(run_id: str, report_data: Dict[str, Any]) -> None:
    ensure_storage()
    _atomic_write_json(run_dir(run_id) / "report.json", report_data)


def load_report(run_id: str) -> Optional[Dict[str, Any]]:
    data = _read_json(run_dir(run_id) / "report.json")
    if isinstance(data, dict):
        return data
    return None


def list_runs() -> List[Dict[str, Any]]:
    ensure_storage()
    runs: List[Dict[str, Any]] = []
    for child in RUNS_DIR.iterdir():
        if child.is_dir():
            meta = load_meta(child.name)
            if meta:
                runs.append(meta)
    runs.sort(key=lambda r: r.get("created_at", ""), reverse=True)
    return runs


def list_run_ids() -> List[str]:
    ensure_storage()
    return [p.name for p in RUNS_DIR.iterdir() if p.is_dir()]
