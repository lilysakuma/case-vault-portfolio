import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app as case_vault


class CaseVaultTests(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"

        self.db_patch = patch.object(
            case_vault, "DB_PATH", self.db_path
        )
        self.db_patch.start()

        case_vault.app.config["TESTING"] = True
        case_vault.init_db()
        case_vault.seed_db()

        self.client = case_vault.app.test_client()

    def tearDown(self):
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def test_homepage_loads(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Phishing Email Report", response.data)

    def test_database_initialization_preserves_data(self):
        response = self.client.get("/init")

        self.assertEqual(response.status_code, 302)

        conn = sqlite3.connect(self.db_path)
        count = conn.execute(
            "SELECT COUNT(*) FROM incidents"
        ).fetchone()[0]
        conn.close()

        self.assertEqual(count, 2)
    def test_create_incident(self):
        response = self.client.post("/incident/create", data={
            "title": "Test Security Incident",
            "description": "Automated test incident",
            "incident_type": "Phishing",
            "status": "new",
            "severity": "3",
            "reporter_id": "1",
            "assignee_id": ""
            
        })

        self.assertEqual(response.status_code, 302)

        conn = sqlite3.connect(self.db_path)
        incident = conn.execute(
            "SELECT * FROM incidents WHERE title = ?",
            ("Test Security Incident",)
        ).fetchone()
        conn.close()

        self.assertIsNotNone(incident)
    def test_edit_incident(self):
        response = self.client.post("/incident/1/edit", data={
            "title": "Updated Security Incident",
            "description": "Updated description",
            "incident_type": "Phishing",
            "status": "investigating",
            "severity": "4",
            "assignee_id": "2"
        })

        self.assertEqual(response.status_code, 302)

        conn = sqlite3.connect(self.db_path)
        incident = conn.execute(
            "SELECT title, status, severity FROM incidents WHERE incident_id = 1"
        ).fetchone()
        conn.close()

        self.assertEqual(incident[0], "Updated Security Incident")
        self.assertEqual(incident[1], "investigating")
        self.assertEqual(incident[2], 4)
        
    def test_delete_incident(self):
        response = self.client.post("/incident/1/delete")

        self.assertEqual(response.status_code, 302)

        conn = sqlite3.connect(self.db_path)
        incident = conn.execute(
            "SELECT * FROM incidents WHERE incident_id = 1"
        ).fetchone()
        conn.close()

        self.assertIsNone(incident)
if __name__ == "__main__":
    unittest.main()