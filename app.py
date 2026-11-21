
# ============================================================
# CASE VAULT - CYBERSECURITY INCIDENT MANAGEMENT SYSTEM
# ============================================================
#
# This Flask application allows users to:
# - View cybersecurity incidents
# - Create, edit, and delete incidents
# - Attach evidence and investigation tasks
# - View affected assets and incident tags
# - Match CVE identifiers with vulnerability information
# - Find potentially related incidents
#
# Data is stored in a local SQLite database.
# ============================================================


# ------------------------------------------------------------
# IMPORTS
# ------------------------------------------------------------

import os
import sqlite3
from pathlib import Path

# Flask handles web requests, HTML templates, redirects,
# and messages displayed to the user.
from flask import Flask, render_template, request, redirect, url_for, flash


# ------------------------------------------------------------
# APPLICATION CONFIGURATION
# ------------------------------------------------------------

# Get the directory containing this Python file.
# This allows the application to locate its database and SQL
# files regardless of the directory it is launched from.
BASE_DIR = Path(__file__).resolve().parent

# Store the SQLite database in the project directory.
DB_PATH = BASE_DIR / "project.db"

# Create the Flask application.
app = Flask(__name__)

# Flask uses a secret key to securely sign session data.
# Use an environment variable if available, otherwise
# generate a temporary key for local development.
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32)


# ============================================================
# DATABASE FUNCTIONS
# ============================================================

def get_db_connection():
    """
    Open a connection to the SQLite database.

    Configure rows so columns can be accessed by name
    and enable foreign key enforcement.
    """

    conn = sqlite3.connect(DB_PATH)

    # Allows access such as incident["title"] instead of
    # relying only on numeric column positions.
    conn.row_factory = sqlite3.Row

    # Enforce relationships between database tables.
    conn.execute("PRAGMA foreign_keys = ON;")

    return conn


def init_db():
    """
    Create the database tables using schema.sql.
    """

    conn = get_db_connection()

    # Locate the SQL file containing CREATE TABLE statements.
    schema_path = BASE_DIR / "schema.sql"

    # executescript() runs multiple SQL statements from a file.
    with open(schema_path, "r", encoding="utf-8") as f:
        conn.executescript(f.read())

    conn.commit()
    conn.close()


def seed_db():
    """
    Populate the database with sample cybersecurity data.

    Sample records include users, incidents, evidence,
    assets, tasks, tags, and vulnerabilities.
    """

    conn = get_db_connection()

    seed_path = BASE_DIR / "seed.sql"

    with open(seed_path, "r", encoding="utf-8") as f:
        conn.executescript(f.read())

    conn.commit()
    conn.close()


# ============================================================
# HOME PAGE - INCIDENT DASHBOARD
# ============================================================

@app.route("/")
def home():
    """
    Display all incidents on the main dashboard.

    Include the reporter's name by joining the incidents
    and users tables.
    """

    conn = get_db_connection()

    incidents = conn.execute("""
        SELECT i.incident_id,
               i.title,
               i.incident_type,
               i.status,
               i.severity,
               i.created_at,
               u.name AS reporter_name

        FROM incidents i

        -- Match each incident to the user who reported it.
        JOIN users u ON i.reporter_id = u.user_id

        -- Display the newest incident IDs first.
        ORDER BY i.incident_id DESC
    """).fetchall()

    conn.close()

    # Send the incident records to the dashboard template.
    return render_template("home.html", incidents=incidents)


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

@app.route("/init")
def initialize_database():
    """
    Initialize the database if it has not been set up.

    Existing incident data is preserved.
    """

    conn = get_db_connection()

    # SQLite stores information about existing tables
    # in its internal sqlite_master table.
    table = conn.execute("""
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
          AND name = 'incidents'
    """).fetchone()

    conn.close()

    # Do not recreate the database if the incidents table exists.
    if table is not None:
        flash("Database already initialized. Existing data was preserved.")
        return redirect(url_for("home"))

    # Create the tables and insert demonstration data.
    init_db()
    seed_db()

    flash("Database created and seeded successfully.")
    return redirect(url_for("home"))


# ============================================================
# RESET DATABASE
# ============================================================

@app.route("/reset", methods=["POST"])
def reset_database():
    """
    Delete and recreate the local demonstration database.

    WARNING: Resetting permanently removes existing local data.
    """

    # Delete the old database file if one exists.
    if DB_PATH.exists():
        DB_PATH.unlink()

    # Rebuild the database using the original schema and seed data.
    init_db()
    seed_db()

    flash("Database reset to sample data.")
    return redirect(url_for("home"))


# ============================================================
# CREATE INCIDENT
# ============================================================

@app.route("/incident/create", methods=["GET", "POST"])
def create_incident():
    """
    Display the incident creation form or save a new incident.

    GET: Show the form.
    POST: Insert a new incident into the database.
    """

    conn = get_db_connection()

    # Retrieve users for the reporter and assignee dropdowns.
    users = conn.execute(
        "SELECT * FROM users ORDER BY name"
    ).fetchall()

    if request.method == "POST":

        # Read submitted form values.
        # strip() removes unnecessary leading/trailing spaces.
        title = request.form["title"].strip()
        description = request.form["description"].strip()
        incident_type = request.form["incident_type"].strip()
        status = request.form["status"]
        severity = request.form["severity"]
        reporter_id = request.form["reporter_id"]

        # An incident does not have to be assigned immediately.
        # Convert an empty assignee value to SQL NULL.
        assignee_id = request.form["assignee_id"] or None

        # Insert the new incident.
        # Question marks are SQL parameters, which prevent
        # form values from being interpreted as SQL commands.
        conn.execute("""
            INSERT INTO incidents
            (
                title,
                description,
                incident_type,
                status,
                severity,
                reporter_id,
                assignee_id,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?,
                    CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """, (
            title,
            description,
            incident_type,
            status,
            severity,
            reporter_id,
            assignee_id
        ))

        # Save the new incident permanently.
        conn.commit()
        conn.close()

        flash("Incident created successfully.")

        # Return to the dashboard after successful creation.
        return redirect(url_for("home"))

    conn.close()

    # A GET request displays the empty creation form.
    return render_template("create_incident.html", users=users)


# ============================================================
# INCIDENT DETAILS
# ============================================================

@app.route("/incident/<int:incident_id>")
def incident_detail(incident_id):
    """
    Display information about one cybersecurity incident.

    Includes:
    - Incident details
    - Evidence
    - Investigation tasks
    - Affected assets
    - Tags
    - Vulnerability enrichment
    - Related incidents
    """

    conn = get_db_connection()

    # --------------------------------------------------------
    # GET INCIDENT INFORMATION
    # --------------------------------------------------------

    incident = conn.execute("""
        SELECT i.*,
               r.name AS reporter_name,
               a.name AS assignee_name

        FROM incidents i

        -- Every incident must have a reporter.
        JOIN users r ON i.reporter_id = r.user_id

        -- LEFT JOIN allows incidents without an assignee.
        LEFT JOIN users a ON i.assignee_id = a.user_id

        WHERE i.incident_id = ?
    """, (incident_id,)).fetchone()

    # Return HTTP 404 if the requested incident does not exist.
    if incident is None:
        conn.close()
        return "Incident not found", 404

    # --------------------------------------------------------
    # GET EVIDENCE
    # --------------------------------------------------------

    # Evidence can include URLs, domains, hashes, CVEs,
    # email headers, or file references.
    evidence_items = conn.execute("""
        SELECT e.*,
               u.name AS added_by_name

        FROM evidence e

        -- Include the name of the user who added the evidence.
        LEFT JOIN users u ON e.added_by = u.user_id

        WHERE e.incident_id = ?

        ORDER BY e.evidence_id DESC
    """, (incident_id,)).fetchall()

    # --------------------------------------------------------
    # GET INVESTIGATION TASKS
    # --------------------------------------------------------

    # Tasks track investigation and response activities,
    # such as triage, containment, and recovery.
    tasks = conn.execute("""
        SELECT t.*,
               u.name AS created_by_name

        FROM tasks t

        JOIN users u ON t.created_by = u.user_id

        WHERE t.incident_id = ?

        ORDER BY t.task_id DESC
    """, (incident_id,)).fetchall()

    # --------------------------------------------------------
    # GET AFFECTED ASSETS
    # --------------------------------------------------------

    # An incident can affect multiple assets.
    # An asset can also appear in multiple incidents.
    #
    # incident_asset is the junction table connecting them.
    assets = conn.execute("""
        SELECT a.*

        FROM assets a

        JOIN incident_asset ia
          ON a.asset_id = ia.asset_id

        WHERE ia.incident_id = ?

        ORDER BY a.asset_id DESC
    """, (incident_id,)).fetchall()

    # --------------------------------------------------------
    # GET INCIDENT TAGS
    # --------------------------------------------------------

    # Tags help categorize incidents.
    # Examples: phishing, critical, vulnerability.
    #
    # incident_tag connects incidents and tags through
    # a many-to-many relationship.
    tags = conn.execute("""
        SELECT t.*

        FROM tags t

        JOIN incident_tag it
          ON t.tag_id = it.tag_id

        WHERE it.incident_id = ?

        ORDER BY t.name
    """, (incident_id,)).fetchall()

    # --------------------------------------------------------
    # VULNERABILITY ENRICHMENT
    # --------------------------------------------------------

    # If an incident contains CVE evidence, match that CVE
    # against the local vulnerabilities table.
    #
    # Example:
    # CVE-2023-34362
    # -> Progress / MOVEit Transfer / SQL Injection
    #
    # This uses local database records, not a live CVE API.
    vuln_matches = conn.execute("""
        SELECT DISTINCT v.*

        FROM vulnerabilities v

        JOIN evidence e
          ON e.value = v.cve_id

        WHERE e.incident_id = ?
          AND e.evidence_type = 'cve'
    """, (incident_id,)).fetchall()

    # --------------------------------------------------------
    # RELATED INCIDENT DETECTION
    # --------------------------------------------------------

    # Look for other incidents sharing evidence values
    # such as CVEs, URLs, domains, or hashes.
    #
    # This can help analysts identify incidents that
    # may involve the same threat or vulnerability.
    #
    # Matching evidence suggests a possible relationship;
    # it does not prove that the incidents are connected.
    #
    # Note: The current query compares evidence values
    # without requiring matching evidence types.
    related_incidents = conn.execute("""
        SELECT DISTINCT
               i.incident_id,
               i.title,
               i.status

        FROM incidents i

        JOIN evidence e2
          ON i.incident_id = e2.incident_id

        -- Exclude the incident currently being viewed.
        WHERE i.incident_id != ?

          -- Find evidence values shared with this incident.
          AND e2.value IN (
              SELECT value

              FROM evidence

              WHERE incident_id = ?
                AND evidence_type IN (
                    'cve',
                    'url',
                    'domain',
                    'hash'
                )
          )

        ORDER BY i.incident_id DESC
    """, (incident_id, incident_id)).fetchall()

    # Retrieve users for any user-related controls
    # displayed on the incident details page.
    users = conn.execute(
        "SELECT * FROM users ORDER BY name"
    ).fetchall()

    conn.close()

    # Send all collected data to the HTML template.
    return render_template(
        "incident_detail.html",
        incident=incident,
        evidence_items=evidence_items,
        tasks=tasks,
        assets=assets,
        tags=tags,
        vuln_matches=vuln_matches,
        related_incidents=related_incidents,
        users=users
    )


# ============================================================
# EDIT INCIDENT
# ============================================================

@app.route("/incident/<int:incident_id>/edit", methods=["GET", "POST"])
def edit_incident(incident_id):
    """
    Display an incident editing form or save changes.

    GET: Show the existing incident information.
    POST: Update the incident in SQLite.
    """

    conn = get_db_connection()

    # Find the incident being edited.
    incident = conn.execute(
        "SELECT * FROM incidents WHERE incident_id = ?",
        (incident_id,)
    ).fetchone()

    # Users can be selected as incident assignees.
    users = conn.execute(
        "SELECT * FROM users ORDER BY name"
    ).fetchall()

    if incident is None:
        conn.close()
        return "Incident not found", 404

    if request.method == "POST":

        # Read updated values from the submitted form.
        title = request.form["title"].strip()
        description = request.form["description"].strip()
        incident_type = request.form["incident_type"].strip()
        status = request.form["status"]
        severity = request.form["severity"]
        assignee_id = request.form["assignee_id"] or None

        # Update only the incident matching this ID.
        # The reporter is not changed by this form.
        conn.execute("""
            UPDATE incidents

            SET title = ?,
                description = ?,
                incident_type = ?,
                status = ?,
                severity = ?,
                assignee_id = ?,
                updated_at = CURRENT_TIMESTAMP

            WHERE incident_id = ?
        """, (
            title,
            description,
            incident_type,
            status,
            severity,
            assignee_id,
            incident_id
        ))

        conn.commit()
        conn.close()

        flash("Incident updated successfully.")

        # Return to the updated incident details page.
        return redirect(
            url_for("incident_detail", incident_id=incident_id)
        )

    conn.close()

    return render_template(
        "edit_incident.html",
        incident=incident,
        users=users
    )


# ============================================================
# DELETE INCIDENT
# ============================================================

@app.route("/incident/<int:incident_id>/delete", methods=["POST"])
def delete_incident(incident_id):
    """
    Delete an incident and its associated records.

    Related records are deleted first to avoid violating
    foreign key constraints.
    """

    conn = get_db_connection()

    # Remove tasks associated with this incident.
    conn.execute(
        "DELETE FROM tasks WHERE incident_id = ?",
        (incident_id,)
    )

    # Remove evidence associated with this incident.
    conn.execute(
        "DELETE FROM evidence WHERE incident_id = ?",
        (incident_id,)
    )

    # Remove many-to-many relationships with tags and assets.
    # The actual tag and asset records are preserved.
    conn.execute(
        "DELETE FROM incident_tag WHERE incident_id = ?",
        (incident_id,)
    )

    conn.execute(
        "DELETE FROM incident_asset WHERE incident_id = ?",
        (incident_id,)
    )

    # Delete the incident after its dependent records.
    conn.execute(
        "DELETE FROM incidents WHERE incident_id = ?",
        (incident_id,)
    )

    conn.commit()
    conn.close()

    flash("Incident deleted successfully.")
    return redirect(url_for("home"))


# ============================================================
# ADD EVIDENCE
# ============================================================

@app.route("/incident/<int:incident_id>/evidence/add",
           methods=["GET", "POST"])
def add_evidence(incident_id):
    """
    Attach evidence to an existing incident.

    The database prevents duplicate evidence entries
    with the same incident, evidence type, and value.
    """

    conn = get_db_connection()

    # Verify that the incident exists before adding evidence.
    incident = conn.execute(
        "SELECT * FROM incidents WHERE incident_id = ?",
        (incident_id,)
    ).fetchone()

    users = conn.execute(
        "SELECT * FROM users ORDER BY name"
    ).fetchall()

    if incident is None:
        conn.close()
        return "Incident not found", 404

    if request.method == "POST":

        # Collect the evidence information from the form.
        evidence_type = request.form["evidence_type"]
        value = request.form["value"].strip()
        added_by = request.form["added_by"]
        file_path = request.form["file_path"].strip()

        try:
            # Store the evidence and associate it with
            # the selected incident and user.
            conn.execute("""
                INSERT INTO evidence
                    (incident_id, evidence_type,
                     value, file_path, added_by)

                VALUES (?, ?, ?, ?, ?)
            """, (
                incident_id,
                evidence_type,
                value,
                file_path or None,
                added_by
            ))

            conn.commit()
            flash("Evidence added successfully.")

        except sqlite3.IntegrityError:
            # The database rejected the insert because an
            # integrity constraint was violated.
            #
            # The existing application displays a duplicate
            # evidence message for this error.
            flash("That evidence already exists for this incident.")

        conn.close()

        return redirect(
            url_for("incident_detail", incident_id=incident_id)
        )

    conn.close()

    return render_template(
        "add_evidence.html",
        incident=incident,
        users=users
    )


# ============================================================
# ADD INVESTIGATION TASK
# ============================================================

@app.route("/incident/<int:incident_id>/task/add",
           methods=["GET", "POST"])
def add_task(incident_id):
    """
    Create an investigation or response task for an incident.

    Tasks help track actions such as triage, containment,
    eradication, recovery, and postmortem review.
    """

    conn = get_db_connection()

    # Verify that the incident exists.
    incident = conn.execute(
        "SELECT * FROM incidents WHERE incident_id = ?",
        (incident_id,)
    ).fetchone()

    users = conn.execute(
        "SELECT * FROM users ORDER BY name"
    ).fetchall()

    if incident is None:
        conn.close()
        return "Incident not found", 404

    if request.method == "POST":

        # Read the task details from the form.
        task_type = request.form["task_type"]
        status = request.form["status"]
        due_date = request.form["due_date"]
        notes = request.form["notes"].strip()
        created_by = request.form["created_by"]

        # Insert the task and associate it with the incident.
        # A blank due date is stored as NULL.
        conn.execute("""
            INSERT INTO tasks
                (incident_id, created_by, task_type,
                 status, due_date, notes)

            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            incident_id,
            created_by,
            task_type,
            status,
            due_date or None,
            notes
        ))

        conn.commit()
        conn.close()

        flash("Task added successfully.")

        return redirect(
            url_for("incident_detail", incident_id=incident_id)
        )

    conn.close()

    return render_template(
        "add_task.html",
        incident=incident,
        users=users
    )


# ============================================================
# START FLASK APPLICATION
# ============================================================

# This block runs only when app.py is executed directly.
# It does not run when the module is imported by unit tests.
if __name__ == "__main__":

    # Disable debug mode for normal local demonstration use.
    # Flask's built-in server is not intended for production.
    app.run(debug=False)
