from __future__ import annotations

from typing import Any, Dict, Optional

from . import seal
from .domain import (ConflictError, NotFoundError, ValidationError, ensure_role,
                     normalize_severity, require_number, require_text)
from .repository import Repository
from .rules import (AUDIT_ROLES, CREATE_ROLES, ENTITY, RECORD_ROLES, SEAL_ENTITY,
                    SEAL_GENERATE_ROLES, SEAL_VERIFY_ROLES, TITLE, VIEW_ROLES,
                    completion_blockers, escalation_required, priority_score,
                    response_deadline_hours, role_for_transition, validate_transition)


class Service:
    def __init__(self, repository: Repository):
        self.repository = repository

    def _view(self, role: str) -> None:
        ensure_role(role, VIEW_ROLES)

    def create_item(self, payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, CREATE_ROLES)
        actor = require_text(actor, "actor", 100)
        title = require_text(payload.get("title"), "title", 200)
        description = require_text(payload.get("description"), "description")
        severity = normalize_severity(payload.get("severity"))
        quantity = require_number(payload.get("quantity", 0), "quantity")
        threshold = require_number(payload.get("threshold", 1), "threshold", 0.000001)
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        item = self.repository.create_item(title, description, severity, quantity,
                                           threshold, external_ref, actor)
        self.repository.append_audit("create", ENTITY, item["id"], actor, {
            "title": title, "severity": severity, "quantity": quantity,
            "priority": priority_score(severity, quantity, threshold),
        })
        return self.enrich(item)

    def add_record(self, item_id: int, payload: Dict[str, Any], actor: str,
                   role: str) -> Dict[str, Any]:
        ensure_role(role, RECORD_ROLES)
        actor = require_text(actor, "actor", 100)
        kind = require_text(payload.get("kind"), "kind", 100)
        detail = require_text(payload.get("detail"), "detail")
        status = payload.get("status", "open")
        if status not in ("open", "closed"):
            raise ValueError("status必须是open或closed")
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        record = self.repository.add_record(item_id, kind, detail, status,
                                            external_ref, actor)
        self.repository.append_audit("record", ENTITY, item_id, actor, {
            "record_id": record["id"], "kind": kind, "status": status,
        })
        return record

    def transition(self, item_id: int, target: str, expected_version: int,
                   actor: str, role: str) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        validate_transition(item["status"], target)
        ensure_role(role, role_for_transition(target))
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValueError("expected_version必须是正整数")
        blockers = completion_blockers(target, self.repository.open_record_count(item_id))
        if blockers:
            from .domain import ConflictError
            raise ConflictError("；".join(blockers))
        updated = self.repository.transition_item(item_id, target, expected_version, actor)
        self.repository.append_audit("transition", ENTITY, item_id, actor, {
            "from": item["status"], "to": target,
            "escalation_required": escalation_required(
                item["severity"], item["quantity"], item["threshold"]),
        })
        return self.enrich(updated)

    def get_item(self, item_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        return self.enrich(self.repository.get_item(item_id))

    def list_items(self, role: str, status: Optional[str] = None) -> list:
        self._view(role)
        return [self.enrich(item) for item in self.repository.list_items(status)]

    def list_records(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_records(item_id)

    def audit(self, role: str, item_id: Optional[int] = None) -> list:
        ensure_role(role, AUDIT_ROLES)
        return self.repository.list_audit(item_id)

    def generate_seal(self, payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, SEAL_GENERATE_ROLES)
        actor = require_text(actor, "actor", 100)
        seal_no = require_text(payload.get("seal_no"), "seal_no", 100)
        end_event_id = payload.get("end_event_id")
        if isinstance(end_event_id, bool) or not isinstance(end_event_id, int) \
                or end_event_id < 1:
            raise ValidationError("end_event_id必须是正整数")
        existing = self.repository.get_seal(seal_no)
        if existing is not None:
            return existing
        events = self.repository.list_audit_until(end_event_id)
        if not events or events[-1]["id"] != end_event_id:
            raise NotFoundError("审计事件不存在")
        bad_event_id = seal.chain_first_bad(events)
        if bad_event_id is not None:
            raise ConflictError(f"审计链在事件{bad_event_id}处已损坏，无法封装")
        package = seal.build_package(seal_no, events)
        try:
            result = self.repository.save_seal(package, actor)
        except ConflictError:
            return self.repository.get_seal(seal_no)
        self.repository.append_audit("seal", SEAL_ENTITY, result["id"], actor, {
            "seal_no": seal_no, "end_event_id": end_event_id,
            "entry_count": result["entry_count"],
        })
        return result

    def get_seal(self, seal_no: str, role: str) -> Dict[str, Any]:
        ensure_role(role, SEAL_VERIFY_ROLES)
        seal_no = require_text(seal_no, "seal_no", 100)
        package = self.repository.get_seal(seal_no)
        if package is None:
            raise NotFoundError("封装不存在")
        return package

    def list_seals(self, role: str) -> list:
        ensure_role(role, SEAL_VERIFY_ROLES)
        return self.repository.list_seals()

    def verify_seal(self, seal_no: str, role: str) -> Dict[str, Any]:
        ensure_role(role, SEAL_VERIFY_ROLES)
        seal_no = require_text(seal_no, "seal_no", 100)
        package = self.repository.get_seal(seal_no)
        if package is None:
            raise NotFoundError("封装不存在")
        events = self.repository.list_audit_until(package["end_event_id"])
        return seal.verify_package(package, events)

    @staticmethod
    def enrich(item: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(item)
        result["priority"] = priority_score(
            item["severity"], item["quantity"], item["threshold"])
        result["deadline_hours"] = response_deadline_hours(
            item["severity"], item["quantity"], item["threshold"])
        result["escalation_required"] = escalation_required(
            item["severity"], item["quantity"], item["threshold"])
        return result
