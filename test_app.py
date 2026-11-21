
# ============================================================
# CASE VAULT - AUTOMATED APPLICATION TESTS
# ============================================================
#
# This file tests the main functionality of the Case Vault
# cybersecurity incident management application.
#
# Tests use Python's built-in unittest framework and Flask's
# test client to simulate requests without starting a server.
#
# IMPORTANT:
# Each test uses a temporary SQLite database, so testing
# does not modify the application's actual project.db file.
#
# Tests cover:
# 1. Homepage loading
# 2. Database initialization and data preservation
# 3. Incident creation
# 4. Incident editing
# 5. Incident deletion
# ============================================================


# ------------------------------------------------------------
# IMPORTS
# ------------------------------------------------------------

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

# Import the Flask application and database functions.
import app as case_vault


# ============================================================
# TEST CLASS
# ============================================================

# unittest.TestCase provides methods for checking whether
# actual results match expected results.
class CaseVaultTests(unittest.TestCase):

    def setUp(self):
        """
        Prepare a clean testing environment before each test.

        Create a temporary database, initialize its tables,
        insert sample records, and configure Flask's test client.
        """

        # Create a temporary directory that will be deleted
        # after the test finishes.
        self.temp_dir = tempfile.TemporaryDirectory()

        # Store the test database inside the temporary directory.
        self.db_path = Path(self.temp_dir.name) / "test.db"

        # Temporarily replace the application's database path.
        # This prevents tests from modifying the real project.db.
        self.db_patch = patch.object(
            case_vault, "DB_PATH", self.db_path
        )
        self.db_patch.start()

        # Enable Flask's testing configuration.
        case_vault.app.config["TESTING"] = True

        # Create database tables and insert the original sample data.
        case_vault.init_db()
        case_vault.seed_db()

        # Flask's test client simulates HTTP requests without
        # requiring the application server to be running.
        self.client = case_vault.app.test_client()

    def tearDown(self):
        """
        Clean up after each test.

        Restore the original database path and delete the
        temporary testing directory.
        """

        # Restore the application's original DB_PATH value.
        self.db_patch.stop()

        # Delete the temporary database and its directory.
        self.temp_dir.cleanup()

    # ========================================================
    # TEST 1 - HOMEPAGE
    # ========================================================

    def test_homepage_loads(self):
        """
        Verify that the homepage loads successfully and
        displays an incident from the sample database.
        """

        # Simulate a browser requesting the homepage.
        response = self.client.get("/")

        # HTTP 200 means the request was successful.
        self.assertEqual(response.status_code, 200)

        # Confirm that the page contains a seeded incident.
        self.assertIn(b"Phishing Email Report", response.data)

    # ========================================================
    # TEST 2 - DATABASE INITIALIZATION
    # ========================================================

    def test_database_initialization_preserves_data(self):
        """
        Verify that initializing an existing database
        does not delete or duplicate its incident records.
        """

        # Request the database initialization route.
        response = self.client.get("/init")

        # HTTP 302 means Flask redirected the request.
        self.assertEqual(response.status_code, 302)

        # Connect to the temporary database.
        conn = sqlite3.connect(self.db_path)

        # Count the incidents remaining after initialization.
        count = conn.execute(
            "SELECT COUNT(*) FROM incidents"
        ).fetchone()[0]

        conn.close()

        # The seed data contains two incidents.
        # Reinitialization should preserve both records.
        self.assertEqual(count, 2)

    # ========================================================
    # TEST 3 - CREATE INCIDENT
    # ========================================================

    def test_create_incident(self):
        """
        Verify that submitting the incident creation form
        inserts a new record into the database.
        """

        # Simulate submitting the incident creation form.
        response = self.client.post("/incident/create", data={
            "title": "Test Security Incident",
            "description": "Automated test incident",
            "incident_type": "Phishing",
            "status": "new",
            "severity": "3",
            "reporter_id": "1",
            "assignee_id": ""
        })

        # A successful creation redirects the user.
        self.assertEqual(response.status_code, 302)

        # Search the temporary database for the new incident.
        conn = sqlite3.connect(self.db_path)

        incident = conn.execute(
            "SELECT * FROM incidents WHERE title = ?",
            ("Test Security Incident",)
        ).fetchone()

        conn.close()

        # Confirm that the new incident was actually saved.
        self.assertIsNotNone(incident)

    # ========================================================
    # TEST 4 - EDIT INCIDENT
    # ========================================================

    def test_edit_incident(self):
        """
        Verify that editing an existing incident updates
        its title, status, and severity in the database.
        """

        # Update the first incident from the sample database.
        response = self.client.post("/incident/1/edit", data={
            "title": "Updated Security Incident",
            "description": "Updated description",
            "incident_type": "Phishing",
            "status": "investigating",
            "severity": "4",
            "assignee_id": "2"
        })

        # Confirm that the application redirected successfully.
        self.assertEqual(response.status_code, 302)

        # Retrieve the updated incident from SQLite.
        conn = sqlite3.connect(self.db_path)

        incident = conn.execute(
            """
            SELECT title, status, severity
            FROM incidents
            WHERE incident_id = 1
            """
        ).fetchone()

        conn.close()

        # Check that the database contains the new values.
        self.assertEqual(incident[0], "Updated Security Incident")
        self.assertEqual(incident[1], "investigating")
        self.assertEqual(incident[2], 4)

    # ========================================================
    # TEST 5 - DELETE INCIDENT
    # ========================================================

    def test_delete_incident(self):
        """
        Verify that deleting an incident removes its
        record from the database.
        """

        # Send a POST request to delete the first incident.
        response = self.client.post("/incident/1/delete")

        # Confirm that Flask redirected after deletion.
        self.assertEqual(response.status_code, 302)

        # Check whether the incident still exists.
        conn = sqlite3.connect(self.db_path)

        incident = conn.execute(
            "SELECT * FROM incidents WHERE incident_id = 1"
        ).fetchone()

        conn.close()

        # None means no matching incident was found.
        self.assertIsNone(incident)


# ============================================================
# RUN TESTS
# ============================================================

# Run the test suite when this file is executed directly.
# unittest automatically discovers methods beginning with test_.
if __name__ == "__main__":
    unittest.main()
