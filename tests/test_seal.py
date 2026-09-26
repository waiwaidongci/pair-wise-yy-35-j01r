import tempfile, unittest
from pathlib import Path
from src.domain import ConflictError, NotFoundError, PermissionDenied, ValidationError
from src.repository import Repository
from src.service import Service


class SealTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)
        self.item = self.service.create_item(
            {"title": "seal item", "description": "seal scenarios", "severity": "high",
             "quantity": 5, "threshold": 10, "external_ref": "SEAL-1"},
            "creator", "dosimetrist")
        self.service.add_record(
            self.item["id"],
            {"kind": "evidence", "detail": "first", "status": "closed",
             "external_ref": "SEAL-EV-1"},
            "recorder", "radiation_officer")

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def _tamper(self, sql, params=()):
        self.repo.conn.execute(sql, params)
        self.repo.conn.commit()

    def _events(self):
        return self.repo.list_audit()

    def test_generate_requires_admin_and_covers_range(self):
        events = self._events()
        end_id = events[-1]["id"]
        with self.assertRaises(PermissionDenied):
            self.service.generate_seal(
                {"seal_no": "S-1", "end_event_id": end_id}, "root", "health_physicist")
        package = self.service.generate_seal(
            {"seal_no": "S-1", "end_event_id": end_id}, "root", "admin")
        self.assertEqual(package["seal_no"], "S-1")
        self.assertEqual(package["start_event_id"], events[0]["id"])
        self.assertEqual(package["end_event_id"], end_id)
        self.assertEqual(package["entry_count"], len(events))
        self.assertEqual(package["start_hash"], events[0]["entry_hash"])
        self.assertEqual(package["end_hash"], events[-1]["entry_hash"])
        self.assertEqual([e["event_id"] for e in package["entries"]],
                         [e["id"] for e in events])
        result = self.service.verify_seal("S-1", "viewer")
        self.assertTrue(result["ok"])
        self.assertIsNone(result["first_bad_event_id"])
        self.assertEqual(result["checked_entries"], len(events))
        with self.assertRaises(PermissionDenied):
            self.service.verify_seal("S-1", "dosimetrist")

    def test_same_seal_no_reuses_first_result(self):
        first_end = self._events()[-1]["id"]
        package = self.service.generate_seal(
            {"seal_no": "S-2", "end_event_id": first_end}, "root", "admin")
        self.service.add_record(
            self.item["id"],
            {"kind": "note", "detail": "later", "status": "closed",
             "external_ref": "SEAL-EV-2"},
            "recorder", "radiation_officer")
        later_end = self._events()[-1]["id"]
        self.assertGreater(later_end, first_end)
        replay = self.service.generate_seal(
            {"seal_no": "S-2", "end_event_id": later_end}, "root", "admin")
        self.assertEqual(replay["end_event_id"], first_end)
        self.assertEqual(replay["entry_count"], package["entry_count"])
        self.assertEqual(replay["end_hash"], package["end_hash"])
        wider = self.service.generate_seal(
            {"seal_no": "S-2B", "end_event_id": later_end}, "root", "admin")
        self.assertGreater(wider["entry_count"], package["entry_count"])

    def test_verify_detects_missing_row(self):
        events = self._events()
        self.service.generate_seal(
            {"seal_no": "S-3", "end_event_id": events[-1]["id"]}, "root", "admin")
        victim = events[0]["id"]
        self._tamper("DELETE FROM audit_events WHERE id=?", (victim,))
        result = self.service.verify_seal("S-3", "viewer")
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "missing")
        self.assertEqual(result["first_bad_event_id"], victim)

    def test_verify_detects_reorder(self):
        events = self._events()
        self.service.generate_seal(
            {"seal_no": "S-4", "end_event_id": events[-1]["id"]}, "root", "admin")
        self._tamper("UPDATE audit_events SET id=? WHERE id=?",
                     (0, events[1]["id"]))
        result = self.service.verify_seal("S-4", "viewer")
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "reordered")
        self.assertEqual(result["first_bad_event_id"], events[0]["id"])

    def test_verify_detects_content_change(self):
        events = self._events()
        self.service.generate_seal(
            {"seal_no": "S-5", "end_event_id": events[-1]["id"]}, "root", "admin")
        target = events[1]["id"]
        self._tamper("UPDATE audit_events SET actor='mallory' WHERE id=?", (target,))
        result = self.service.verify_seal("S-5", "viewer")
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "modified")
        self.assertEqual(result["first_bad_event_id"], target)

    def test_events_after_sealing_are_not_mixed_in(self):
        end_id = self._events()[-1]["id"]
        self.service.generate_seal(
            {"seal_no": "S-6", "end_event_id": end_id}, "root", "admin")
        self.service.add_record(
            self.item["id"],
            {"kind": "note", "detail": "after seal", "status": "closed",
             "external_ref": "SEAL-EV-3"},
            "recorder", "radiation_officer")
        self.assertTrue(self.service.verify_seal("S-6", "viewer")["ok"])
        later_id = self._events()[-1]["id"]
        self.assertGreater(later_id, end_id)
        self._tamper("UPDATE audit_events SET actor='mallory' WHERE id=?", (later_id,))
        self.assertTrue(self.service.verify_seal("S-6", "viewer")["ok"])

    def test_unknown_end_event_and_unknown_seal(self):
        with self.assertRaises(NotFoundError):
            self.service.generate_seal(
                {"seal_no": "S-7", "end_event_id": 9999}, "root", "admin")
        with self.assertRaises(NotFoundError):
            self.service.verify_seal("NOPE", "viewer")
        with self.assertRaises(NotFoundError):
            self.service.get_seal("NOPE", "viewer")
        with self.assertRaises(ValidationError):
            self.service.generate_seal({"seal_no": "S-7B"}, "root", "admin")

    def test_refuse_to_seal_broken_chain(self):
        events = self._events()
        self._tamper("UPDATE audit_events SET actor='mallory' WHERE id=?",
                     (events[0]["id"],))
        with self.assertRaises(ConflictError):
            self.service.generate_seal(
                {"seal_no": "S-8", "end_event_id": events[-1]["id"]}, "root", "admin")


if __name__ == "__main__":
    unittest.main()
