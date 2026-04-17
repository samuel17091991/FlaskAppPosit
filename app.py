import os
import uuid
import json
import re
import datetime
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv
from ad_access import enforce_access
import psycopg2
import psycopg2.extras

load_dotenv()


class PrefixMiddleware:
    """Strip /content/<guid> prefix that Posit Connect adds to PATH_INFO."""
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        path_info = environ.get('PATH_INFO', '')
        match = re.match(r'(/content/[^/]+)(.*)', path_info)
        if match:
            environ['SCRIPT_NAME'] = match.group(1)
            environ['PATH_INFO'] = match.group(2) or '/'
        return self.wsgi_app(environ, start_response)


_base_dir = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, template_folder=os.path.join(_base_dir, 'templates'))
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-key-change-in-prod")
app.wsgi_app = PrefixMiddleware(app.wsgi_app)
enforce_access(app)

DB_CONFIG = {
    "host": os.getenv("DB_HOST"),
    "database": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "port": os.getenv("DB_PORT", 5432),
}

SELECT_COLUMNS = """
    id, attandance_id, user_name, user_email, node_id, dept_id,
    role, function, attandance_expectation, meeting_date,
    attendee_type, primary_node_yn, active_yn,
    created_by, created_date, modified_by, modified_date
"""


def get_db_connection():
    conn = psycopg2.connect(**DB_CONFIG)
    conn.autocommit = True
    return conn


def serialize_row(row):
    """Convert a RealDictCursor row to a JSON-safe dict."""
    out = {}
    for key, val in row.items():
        if isinstance(val, (datetime.datetime, datetime.date)):
            out[key] = val.isoformat()
        elif isinstance(val, uuid.UUID):
            out[key] = str(val)
        else:
            out[key] = val
    return out


# ---------- Page ----------
@app.route("/")
def index():
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(f"""
            SELECT {SELECT_COLUMNS}
            FROM clin_trial_fnd_ref.pd_kpi_meeting_attandance
            ORDER BY created_date DESC
            LIMIT 500
        """)
        rows = [serialize_row(r) for r in cur.fetchall()]
        cur.close()
        conn.close()
        return render_template("index.html", rows_json=json.dumps(rows), error=None)
    except Exception as e:
        return render_template("index.html", rows_json="[]", error=str(e))


# ---------- API: List ----------
@app.route("/api/records", methods=["GET"])
def api_list_records():
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(f"""
            SELECT {SELECT_COLUMNS}
            FROM clin_trial_fnd_ref.pd_kpi_meeting_attandance
            ORDER BY created_date DESC
            LIMIT 500
        """)
        rows = [serialize_row(r) for r in cur.fetchall()]
        cur.close()
        conn.close()
        return jsonify(rows)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------- API: Create ----------
@app.route("/api/records", methods=["POST"])
def api_create_record():
    try:
        data = request.get_json()
        new_id = str(uuid.uuid4())
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(f"""
            INSERT INTO clin_trial_fnd_ref.pd_kpi_meeting_attandance
                (id, user_name, user_email, node_id, dept_id, role,
                 function, attandance_expectation, meeting_date,
                 attendee_type, primary_node_yn, active_yn,
                 created_by, created_date)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                    CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
            RETURNING {SELECT_COLUMNS}
        """, (
            new_id,
            data.get("user_name") or None,
            data.get("user_email") or None,
            data.get("node_id") or None,
            data.get("dept_id") or None,
            data.get("role") or None,
            data.get("function") or None,
            data.get("attandance_expectation") or None,
            data.get("meeting_date") or None,
            data.get("attendee_type") or None,
            data.get("primary_node_yn") or None,
            data.get("active_yn") or None,
            data.get("created_by") or None,
        ))
        row = serialize_row(cur.fetchone())
        cur.close()
        conn.close()
        return jsonify(row), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------- API: Update ----------
@app.route("/api/records/<record_id>", methods=["PUT"])
def api_update_record(record_id):
    try:
        data = request.get_json()
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(f"""
            UPDATE clin_trial_fnd_ref.pd_kpi_meeting_attandance
            SET user_name = %s, user_email = %s, node_id = %s,
                dept_id = %s, role = %s, function = %s,
                attandance_expectation = %s, meeting_date = %s,
                attendee_type = %s, primary_node_yn = %s, active_yn = %s,
                modified_by = %s,
                modified_date = CURRENT_TIMESTAMP AT TIME ZONE 'UTC'
            WHERE id = %s
            RETURNING {SELECT_COLUMNS}
        """, (
            data.get("user_name") or None,
            data.get("user_email") or None,
            data.get("node_id") or None,
            data.get("dept_id") or None,
            data.get("role") or None,
            data.get("function") or None,
            data.get("attandance_expectation") or None,
            data.get("meeting_date") or None,
            data.get("attendee_type") or None,
            data.get("primary_node_yn") or None,
            data.get("active_yn") or None,
            data.get("modified_by") or None,
            record_id,
        ))
        row = cur.fetchone()
        cur.close()
        conn.close()
        if not row:
            return jsonify({"error": "Record not found"}), 404
        return jsonify(serialize_row(row))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------- API: Delete ----------
@app.route("/api/records/<record_id>", methods=["DELETE"])
def api_delete_record(record_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            DELETE FROM clin_trial_fnd_ref.pd_kpi_meeting_attandance
            WHERE id = %s
        """, (record_id,))
        deleted = cur.rowcount
        cur.close()
        conn.close()
        if deleted == 0:
            return jsonify({"error": "Record not found"}), 404
        return jsonify({"success": True}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True, port=5000)
