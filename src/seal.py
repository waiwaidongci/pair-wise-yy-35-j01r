from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional

from .audit import utc_now
from .domain import ValidationError

GENESIS = "GENESIS"
PACKAGE_PREFIX = "SEAL"
_ROOT_SEED = "AUDIT_PACKAGE_ROOT"

_EVENT_FIELDS = ("id", "action", "entity_type", "entity_id", "actor",
                 "detail", "previous_hash", "entry_hash", "created_at")


def canonical_event(event: Dict[str, Any]) -> str:
    payload = {field: event[field] for field in _EVENT_FIELDS}
    return json.dumps(payload, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str)


def event_digest(event: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_event(event).encode("utf-8")).hexdigest()


def package_number(end_event_id: int) -> str:
    return f"{PACKAGE_PREFIX}-{int(end_event_id):08d}"


def fold_root(digests: List[str]) -> str:
    root = _ROOT_SEED
    for digest in digests:
        root = hashlib.sha256((root + ":" + digest).encode("utf-8")).hexdigest()
    return root


def build_package(events: List[Dict[str, Any]], end_event_id: int,
                  actor: str) -> Dict[str, Any]:
    """按原顺序对截止 end_event_id 的连续事件快照生成完整性包（纯规则）。"""
    end_event_id = int(end_event_id)
    if not events:
        raise ValidationError("结束事件不存在，无法封装")
    previous_hash = GENESIS
    previous_id = 0
    entries: List[Dict[str, Any]] = []
    digests: List[str] = []
    for event in events:
        event_id = int(event["id"])
        if event_id != previous_id + 1:
            raise ValidationError("审计事件缺行，无法封装")
        if event["previous_hash"] != previous_hash:
            raise ValidationError("审计链断裂，无法封装")
        previous_id = event_id
        previous_hash = event["entry_hash"]
        digest = event_digest(event)
        entries.append({"event_id": event_id, "digest": digest})
        digests.append(digest)
    if entries[-1]["event_id"] != end_event_id:
        raise ValidationError("结束事件不在封装范围内")
    return {
        "package_no": package_number(end_event_id),
        "start_event_id": entries[0]["event_id"],
        "end_event_id": end_event_id,
        "start_digest": digests[0],
        "end_digest": digests[-1],
        "event_count": len(entries),
        "entry_digests": entries,
        "root_digest": fold_root(digests),
        "created_by": actor,
        "created_at": utc_now(),
    }


def _failure(event_id: int, reason: str, message: str,
             checked: int) -> Dict[str, Any]:
    return {"ok": False, "first_anomaly_event_id": event_id,
            "reason": reason, "message": message, "checked_count": checked}


def verify_package(package: Dict[str, Any],
                   events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """按封装时的原顺序逐条重算摘要；缺行/重排/改动均返回首个异常事件ID。"""
    sealed_entries = package["entry_digests"]
    if isinstance(sealed_entries, str):
        sealed_entries = json.loads(sealed_entries)
    current = {int(event["id"]): event for event in events}
    previous_hash = GENESIS
    checked = 0
    for sealed in sealed_entries:
        event_id = int(sealed["event_id"])
        event = current.pop(event_id, None)
        if event is None:
            return _failure(event_id, "missing_row", "审计事件缺行", checked)
        if event_digest(event) != sealed["digest"]:
            return _failure(event_id, "digest_mismatch",
                            "审计条目内容或排列与封装不一致", checked)
        if event["previous_hash"] != previous_hash:
            return _failure(event_id, "broken_chain",
                            "审计链断裂，事件可能被重排", checked)
        previous_hash = event["entry_hash"]
        checked += 1
    if current:
        extra_id = min(current)
        return _failure(extra_id, "unexpected_row",
                        "封装范围内存在未封装事件", checked)
    return {"ok": True, "first_anomaly_event_id": None, "reason": None,
            "message": "完整性校验通过", "checked_count": checked}
