import json
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path

from src.domain import NotFoundError, PermissionDenied
from src.http_api import make_handler
from src.repository import Repository
from src.seal import build_package, event_digest, verify_package
from src.service import Service


class SealTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)
        for ref in ("SEAL-1", "SEAL-2"):
            self.service.create_item(
                {"title": ref, "description": "seal flow", "severity": "high",
                 "quantity": 5, "threshold": 10, "external_ref": ref},
                "creator", "dosimetrist")

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def _seal(self, end_event_id, actor="root", role="admin"):
        return self.service.seal_package(end_event_id, actor, role)

    def test_package_fields_and_verify(self):
        events = self.repo.list_audit()
        end_id = events[-1]["id"]
        package = self._seal(end_id)
        self.assertEqual(package["package_no"], f"SEAL-{end_id:08d}")
        self.assertEqual(package["start_event_id"], 1)
        self.assertEqual(package["end_event_id"], end_id)
        self.assertEqual(package["event_count"], len(events))
        self.assertEqual(package["start_digest"], event_digest(events[0]))
        self.assertEqual(package["end_digest"], event_digest(events[-1]))
        self.assertEqual([e["event_id"] for e in package["entry_digests"]],
                         [e["id"] for e in events])
        self.assertFalse(package["reused"])
        result = self.service.verify_package(package["package_no"], "viewer")
        self.assertTrue(result["ok"])
        self.assertIsNone(result["first_anomaly_event_id"])
        self.assertEqual(result["checked_count"], len(events))

    def test_retry_same_end_event_reuses_first_result(self):
        end_id = self.repo.list_audit()[-1]["id"]
        first = self._seal(end_id, actor="root")
        again = self._seal(end_id, actor="another-admin")
        self.assertTrue(again["reused"])
        self.assertEqual(again["package_no"], first["package_no"])
        self.assertEqual(again["root_digest"], first["root_digest"])
        self.assertEqual(again["created_by"], "root")
        self.assertEqual(again["created_at"], first["created_at"])
        self.assertEqual(len(self.repo.list_audit_packages()), 1)

    def test_old_package_excludes_later_events(self):
        first_end = self.repo.list_audit()[-1]["id"]
        package = self._seal(first_end)
        for ref in ("SEAL-3", "SEAL-4"):
            self.service.create_item(
                {"title": ref, "description": "after seal", "severity": "low",
                 "quantity": 1, "threshold": 1, "external_ref": ref},
                "creator", "dosimetrist")
        result = self.service.verify_package(package["package_no"], "viewer")
        self.assertTrue(result["ok"])
        self.assertEqual(result["checked_count"], package["event_count"])
        stored = self.repo.get_audit_package(package["package_no"])
        self.assertEqual(stored["end_event_id"], first_end)

    def test_missing_row_reports_first_gap(self):
        end_id = self.repo.list_audit()[-1]["id"]
        package = self._seal(end_id)
        with self.repo._lock, self.repo.conn:
            self.repo.conn.execute("DELETE FROM audit_events WHERE id=2")
        result = self.service.verify_package(package["package_no"], "health_physicist")
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_anomaly_event_id"], 2)
        self.assertEqual(result["reason"], "missing_row")
        self.assertEqual(result["checked_count"], 1)

    def test_content_change_reports_changed_event(self):
        end_id = self.repo.list_audit()[-1]["id"]
        package = self._seal(end_id)
        with self.repo._lock, self.repo.conn:
            self.repo.conn.execute(
                "UPDATE audit_events SET action='tampered' WHERE id=1")
        result = self.service.verify_package(package["package_no"], "viewer")
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_anomaly_event_id"], 1)
        self.assertEqual(result["reason"], "digest_mismatch")

    def test_reorder_reports_first_moved_event(self):
        end_id = self.repo.list_audit()[-1]["id"]
        package = self._seal(end_id)
        with self.repo._lock, self.repo.conn:
            # 物理交换相邻两行的位置（ID互换）模拟重排
            self.repo.conn.execute("UPDATE audit_events SET id=999 WHERE id=1")
            self.repo.conn.execute("UPDATE audit_events SET id=1 WHERE id=2")
            self.repo.conn.execute("UPDATE audit_events SET id=2 WHERE id=999")
        result = self.service.verify_package(package["package_no"], "viewer")
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_anomaly_event_id"], 1)

    def test_permission_and_validation(self):
        end_id = self.repo.list_audit()[-1]["id"]
        with self.assertRaises(PermissionDenied):
            self.service.seal_package(end_id, "x", "health_physicist")
        with self.assertRaises(PermissionDenied):
            self.service.seal_package(end_id, "x", "viewer")
        with self.assertRaises(NotFoundError):
            self._seal(9999)
        for bad in (0, -1, "2", 2.0, True, None):
            with self.assertRaises(ValueError):
                self._seal(bad)
        with self.assertRaises(NotFoundError):
            self.service.get_package("SEAL-00009999", "viewer")

    def test_build_rejects_gapped_chain(self):
        events = self.repo.list_audit()
        events = [e for e in events if e["id"] != 1]
        with self.assertRaises(Exception):
            build_package(events, events[-1]["id"], "root")

    def test_verify_flags_extra_row_in_range(self):
        events = self.repo.list_audit()
        package = self._seal(events[-1]["id"])
        events.append(dict(events[-1]))
        events[-1]["id"] = events[-2]["id"] + 1
        result = verify_package(package, events)
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "unexpected_row")


class SealHttpTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "http.db"))
        self.service = Service(self.repo)
        server = ThreadingHTTPServer(
            ("127.0.0.1", 0), make_handler(self.service, "."))
        self.port = server.server_address[1]
        self.thread = threading.Thread(target=server.serve_forever, daemon=True)
        self.thread.start()
        self.server = server

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.repo.close()
        self.tmp.cleanup()

    def _request(self, method, path, role, body=None):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=5)
        payload = json.dumps(body).encode("utf-8") if body is not None else None
        conn.request(method, path, body=payload,
                     headers={"X-Actor": "root", "X-Role": role,
                              "Content-Type": "application/json"})
        resp = conn.getresponse()
        data = json.loads(resp.read().decode("utf-8"))
        conn.close()
        return resp.status, data

    def test_seal_endpoints_over_http(self):
        self.service.create_item(
            {"title": "http", "description": "http seal", "severity": "low",
             "quantity": 1, "threshold": 1}, "creator", "dosimetrist")
        end_id = self.repo.list_audit()[-1]["id"]

        status, _ = self._request("POST", "/api/audit/packages", "viewer",
                                  {"end_event_id": end_id})
        self.assertEqual(status, 403)

        status, created = self._request("POST", "/api/audit/packages", "admin",
                                        {"end_event_id": end_id})
        self.assertEqual(status, 201)
        package_no = created["package_no"]

        status, retried = self._request("POST", "/api/audit/packages", "admin",
                                        {"end_event_id": end_id})
        self.assertEqual(status, 201)
        self.assertTrue(retried["reused"])
        self.assertEqual(retried["package_no"], package_no)

        status, fetched = self._request(
            "GET", f"/api/audit/packages/{package_no}", "viewer")
        self.assertEqual(status, 200)
        self.assertEqual(fetched["event_count"], created["event_count"])

        status, result = self._request(
            "GET", f"/api/audit/packages/{package_no}/verify", "viewer")
        self.assertEqual(status, 200)
        self.assertTrue(result["ok"])

        with self.repo._lock, self.repo.conn:
            self.repo.conn.execute("DELETE FROM audit_events WHERE id=1")
        status, result = self._request(
            "GET", f"/api/audit/packages/{package_no}/verify", "viewer")
        self.assertEqual(status, 200)
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_anomaly_event_id"], 1)


if __name__ == "__main__":
    unittest.main()
