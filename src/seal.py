from __future__ import annotations

from typing import Any, Dict, List, Optional

from .audit import calculate_hash

GENESIS = "GENESIS"


def _payload(event: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "action": event["action"],
        "entity_type": event["entity_type"],
        "entity_id": event["entity_id"],
        "actor": event["actor"],
        "detail": event["detail"],
        "created_at": event["created_at"],
    }


def chain_first_bad(events: List[Dict[str, Any]]) -> Optional[int]:
    previous = GENESIS
    for event in events:
        if event["previous_hash"] != previous:
            return event["id"]
        if calculate_hash(previous, _payload(event)) != event["entry_hash"]:
            return event["id"]
        previous = event["entry_hash"]
    return None


def build_package(seal_no: str, events: List[Dict[str, Any]]) -> Dict[str, Any]:
    entries = [
        {"seq": index + 1, "event_id": event["id"], "entry_hash": event["entry_hash"]}
        for index, event in enumerate(events)
    ]
    return {
        "seal_no": seal_no,
        "start_event_id": events[0]["id"],
        "end_event_id": events[-1]["id"],
        "entry_count": len(events),
        "start_hash": events[0]["entry_hash"],
        "end_hash": events[-1]["entry_hash"],
        "entries": entries,
    }


def _result(package: Dict[str, Any], ok: bool, reason: str, message: str,
            first_bad: Optional[int], checked: int) -> Dict[str, Any]:
    return {
        "seal_no": package["seal_no"],
        "ok": ok,
        "reason": reason,
        "message": message,
        "first_bad_event_id": first_bad,
        "checked_entries": checked,
    }


def verify_package(package: Dict[str, Any], events: List[Dict[str, Any]]) -> Dict[str, Any]:
    entries = package["entries"]
    if package["entry_count"] != len(entries):
        return _result(package, False, "package_corrupt", "封装条目数与明细不一致", None, 0)
    if entries and (package["start_hash"] != entries[0]["entry_hash"]
                    or package["end_hash"] != entries[-1]["entry_hash"]):
        return _result(package, False, "package_corrupt", "封装起止摘要与明细不一致", None, 0)
    actual_ids = {event["id"] for event in events}
    previous = GENESIS
    for index, stored in enumerate(entries):
        if index >= len(events):
            return _result(package, False, "missing", "审计事件缺失",
                           stored["event_id"], index)
        event = events[index]
        if event["id"] != stored["event_id"]:
            if stored["event_id"] in actual_ids:
                return _result(package, False, "reordered", "审计事件顺序被调整",
                               stored["event_id"], index)
            return _result(package, False, "missing", "审计事件缺失",
                           stored["event_id"], index)
        if (event["previous_hash"] != previous
                or calculate_hash(previous, _payload(event)) != stored["entry_hash"]
                or event["entry_hash"] != stored["entry_hash"]):
            return _result(package, False, "modified", "审计事件内容被改动",
                           event["id"], index)
        previous = stored["entry_hash"]
    if len(events) > len(entries):
        extra = events[len(entries)]
        return _result(package, False, "unexpected", "封装范围内出现额外审计事件",
                       extra["id"], len(entries))
    return _result(package, True, "ok", "校验通过", None, len(entries))
