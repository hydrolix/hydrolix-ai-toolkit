from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any


def _load_baselines_module() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_bot_insights_baselines", Path(__file__).resolve().parent.parent / "baselines.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load sibling baselines.py module.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


baselines = _load_baselines_module()


clean_number = baselines.clean_number


confidence = baselines.confidence


direction = baselines.direction


json_safe = baselines.json_safe


json_safe_metadata_value = baselines.json_safe_metadata_value


metadata_text = baselines.metadata_text


pct_delta = baselines.pct_delta


support_counts = baselines.support_counts


to_number = baselines.to_number
