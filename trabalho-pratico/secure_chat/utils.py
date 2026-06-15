import base64
import json
from datetime import datetime, timezone
from pathlib import Path


def b64e(data):
    return base64.b64encode(data).decode("ascii")


def b64d(value):
    return base64.b64decode(value.encode("ascii"))


def canonical_json(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def ensure_parent_dir(path):
    Path(path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)

