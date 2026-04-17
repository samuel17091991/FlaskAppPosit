"""
ad_access.py — Active Directory Access Control for Posit Connect Apps
======================================================================
Reusable module for managing user authentication and authorization
in Python Dash/Flask apps deployed on Posit Connect with PAM authentication.

Uses:
  - RStudio-Connect-Credentials header for tamper-proof user identity
  - adquery Linux command for AD group membership checks
  - adquery user lookup for auto-detecting display names

Setup:
  1. Copy this file into your app directory
  2. Set environment variables in Posit Connect:
     - REQUIRED_AD_GROUP: AD group name for app access (e.g., L_MACH_Creative)
     - RLS_ADMINS: Comma-separated admin user IDs (e.g., l034698,l010793)
  3. Add the middleware to your Flask/Dash app (see examples below)

Requirements:
  - adquery must be available on the Posit Connect server (/usr/bin/adquery)
  - Posit Connect must use PAM authentication
  - RStudio-Connect-Credentials header must be enabled (default for PAM)

Example Usage in Dash:
    from ad_access import get_current_user, is_admin, check_ad_group, get_user_display_name, enforce_access
    app = dash.Dash(__name__)
    server = app.server
    enforce_access(server)  # Add AD group check middleware
    # In callbacks:
    user_id = get_current_user()
    if is_admin(user_id): ...

Example Usage in Flask:
    from ad_access import enforce_access
    app = Flask(__name__)
    enforce_access(app)
"""

import os
import json
import subprocess
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# ═════════════════════════════════════════════════════════════════════
#  CONFIGURATION (from environment variables)
# ═════════════════════════════════════════════════════════════════════

# Admin user IDs who bypass all access checks and see all data
RLS_ADMINS = [x.strip().lower()
    for x in os.getenv("RLS_ADMINS", "").split(",") if x.strip()]

# AD group required to access the app (empty = no group check)
REQUIRED_AD_GROUP = os.getenv("REQUIRED_AD_GROUP", "")

# Fallback user ID for local development (not used in production)
_FALLBACK_USER = os.getenv("APP_USER", "unknown")

# Manual user ID → display name overrides (JSON string)
# Example: USER_NAME_MAP={"l034698":"Giridhar S","l045123":"Aswin VM"}
_user_name_map = {}
try:
    _user_name_map = json.loads(os.getenv("USER_NAME_MAP", "{}"))
except Exception:
    pass


# ═════════════════════════════════════════════════════════════════════
#  CACHES (avoid repeated adquery calls)
# ═════════════════════════════════════════════════════════════════════

_auth_cache = {}    # {user_id:group -> (bool, timestamp)}
_name_cache = {}    # {user_id -> display_name}
_groups_cache = {}  # {user_id -> ([groups], timestamp)}

CACHE_TTL = 300  # 5 minutes


# ═════════════════════════════════════════════════════════════════════
#  USER IDENTITY
# ═════════════════════════════════════════════════════════════════════

def get_current_user():
    """Get the authenticated user ID from Posit Connect request header.

    Returns the real user ID set by Posit Connect (cannot be spoofed).
    Falls back to APP_USER env var for local development.

    Returns:
        str: User ID (e.g., 'l034698')
    """
    try:
        from flask import request
        creds = request.headers.get("RStudio-Connect-Credentials", "")
        if creds:
            data = json.loads(creds)
            return data.get("user", _FALLBACK_USER)
    except Exception:
        pass
    return _FALLBACK_USER


def get_user_display_name(user_id=None):
    """Get user's full display name.

    Priority: USER_NAME_MAP env var > adquery lookup > empty string.
    Results are cached to avoid repeated adquery calls.

    Args:
        user_id: Optional user ID. If None, uses current authenticated user.

    Returns:
        str: Display name (e.g., 'Giridhar S') or empty string.

    Example:
        name = get_user_display_name('l034698')  # Returns 'Giridhar S'
        name = get_user_display_name()  # Uses current user
    """
    if user_id is None:
        user_id = get_current_user()

    # 1. Check manual map
    if user_id in _user_name_map:
        return _user_name_map[user_id]

    # 2. Check cache
    if user_id in _name_cache:
        return _name_cache[user_id]

    # 3. Auto-detect from AD
    #    adquery user l034698 returns:
    #    l034698:x:52423:7546:giridhar s:/home/l034698:/bin/bash
    #    The 5th field (index 4) is the display name
    try:
        result = subprocess.run(
            ["adquery", "user", user_id],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            parts = result.stdout.strip().split(":")
            if len(parts) >= 5 and parts[4].strip():
                ad_name = parts[4].strip().title()
                _name_cache[user_id] = ad_name
                logger.info("Auto-detected name for %s: %s", user_id, ad_name)
                return ad_name
    except Exception as e:
        logger.warning("AD name lookup failed for %s: %s", user_id, e)

    _name_cache[user_id] = ""
    return ""


# ═════════════════════════════════════════════════════════════════════
#  ADMIN CHECK
# ═════════════════════════════════════════════════════════════════════

def is_admin(user_id=None):
    """Check if user is an admin/manager.

    Admins bypass AD group checks and see all data.
    Configure via RLS_ADMINS environment variable.

    Args:
        user_id: Optional user ID. If None, uses current authenticated user.

    Returns:
        bool: True if user is in RLS_ADMINS list.

    Example:
        if is_admin():
            show_all_data()
        else:
            show_user_data_only()
    """
    if user_id is None:
        user_id = get_current_user()
    return user_id.lower() in RLS_ADMINS


# ═════════════════════════════════════════════════════════════════════
#  AD GROUP CHECK
# ═════════════════════════════════════════════════════════════════════

def check_ad_group(user_id=None, group_name=None):
    """Check if user belongs to a specific AD group via adquery.

    Results cached for 5 minutes. On failure, denies access (secure default).

    The adquery command returns lines like:
        am.lilly.com/Groups/Universal Groups/L_MACH_Creative
    The check looks for the group name anywhere in the output.

    Args:
        user_id: Optional user ID. If None, uses current authenticated user.
        group_name: AD group name to check. If None, uses REQUIRED_AD_GROUP env var.

    Returns:
        bool: True if user is in the group, False otherwise.

    Example:
        if check_ad_group('l045123', 'L_MACH_Creative'):
            print("User is in the group")
    """
    if user_id is None:
        user_id = get_current_user()
    if not group_name:
        group_name = REQUIRED_AD_GROUP
    if not group_name:
        return True  # No group check configured

    # Check cache
    cache_key = f"{user_id}:{group_name}"
    now = datetime.now().timestamp()
    if cache_key in _auth_cache:
        result, ts = _auth_cache[cache_key]
        if now - ts < CACHE_TTL:
            return result

    # Query AD
    try:
        result = subprocess.run(
            ["adquery", "user", "-a", user_id],
            capture_output=True, text=True, timeout=10
        )
        authorized = group_name in result.stdout
        _auth_cache[cache_key] = (authorized, now)
        return authorized
    except Exception as e:
        logger.warning("AD group check failed for %s: %s — denying access", user_id, e)
        _auth_cache[cache_key] = (False, now)
        return False  # DENY on failure (secure default)


def get_user_groups(user_id=None):
    """Get all AD groups for a user.

    Results cached for 5 minutes.

    Args:
        user_id: Optional user ID. If None, uses current authenticated user.

    Returns:
        list: List of group names (last part of the path).

    Example:
        groups = get_user_groups('l034698')
        # Returns: ['CARK00001', 'AADS_CoP_AI_ML_NLP', 'L_MACH_Creative', ...]
    """
    if user_id is None:
        user_id = get_current_user()

    # Check cache
    now = datetime.now().timestamp()
    if user_id in _groups_cache:
        groups, ts = _groups_cache[user_id]
        if now - ts < CACHE_TTL:
            return groups

    try:
        result = subprocess.run(
            ["adquery", "user", "-a", user_id],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            groups = []
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if "/" in line:
                    group_name = line.rsplit("/", 1)[-1].strip()
                    if group_name:
                        groups.append(group_name)
                elif line:
                    groups.append(line)
            _groups_cache[user_id] = (groups, now)
            return groups
    except Exception as e:
        logger.warning("Failed to get groups for %s: %s", user_id, e)

    _groups_cache[user_id] = ([], now)
    return []


def is_in_any_group(user_id=None, group_names=None):
    """Check if user is in ANY of the specified AD groups.

    Useful when multiple groups should have access.

    Args:
        user_id: Optional user ID.
        group_names: List of AD group names to check.

    Returns:
        bool: True if user is in at least one of the groups.

    Example:
        if is_in_any_group(groups=['L_MACH_Creative', 'L_MACH_Managers']):
            grant_access()
    """
    if not group_names:
        return True
    if user_id is None:
        user_id = get_current_user()
    user_groups = get_user_groups(user_id)
    return any(g in user_groups for g in group_names)


# ═════════════════════════════════════════════════════════════════════
#  ROW-LEVEL SECURITY
# ═════════════════════════════════════════════════════════════════════

def apply_rls(df, name_column="DesignerAssigned"):
    """Filter DataFrame based on Row-Level Security.

    Admins see all rows. Non-admins see only rows matching their display name.
    If a non-admin has no name mapping, returns empty DataFrame (secure default).

    Args:
        df: pandas DataFrame to filter.
        name_column: Column name containing the user/designer name.

    Returns:
        DataFrame: Filtered (or unfiltered for admins).

    Example:
        df = read_all_projects()
        visible_df = apply_rls(df, name_column='DesignerAssigned')
    """
    import pandas as pd

    user_id = get_current_user()
    if is_admin(user_id) or df.empty:
        return df

    display_name = get_user_display_name(user_id)
    if not display_name:
        logger.warning("User %s has no name mapping — showing empty data", user_id)
        return df.iloc[0:0]  # Empty DataFrame, same columns

    if name_column in df.columns:
        return df[df[name_column].str.strip().str.upper() == display_name.strip().upper()]
    return df


# ═════════════════════════════════════════════════════════════════════
#  FLASK/DASH MIDDLEWARE
# ═════════════════════════════════════════════════════════════════════

ACCESS_DENIED_HTML = """
<!DOCTYPE html>
<html><head><title>Access Denied</title></head>
<body style="font-family:Arial; text-align:center; margin-top:100px; background:#F8FAFC;">
<div style="max-width:500px; margin:auto; padding:40px; background:white; border-radius:12px; box-shadow:0 2px 10px rgba(0,0,0,0.1);">
<h1 style="color:#EF4444; font-size:48px;">&#9888;</h1>
<h2 style="color:#EF4444;">Access Denied</h2>
<p style="color:#64748B; font-size:16px;">You do not have permission to access this application.</p>
<p style="color:#94A3B8; font-size:14px;">
Please request access to the required Active Directory group.<br>
Contact your system administrator for assistance.</p>
<p style="color:#CBD5E1; font-size:12px; margin-top:30px;">
Required group: {group_name}</p>
</div></body></html>
"""


def enforce_access(server_app, group_name=None, admin_list=None):
    """Add AD group check middleware to a Flask/Dash server.

    Call this once after creating your app. Every request will be checked.
    Admins bypass the group check. Results are cached for 5 minutes.

    Args:
        server_app: Flask app or Dash server (app.server)
        group_name: AD group name. If None, uses REQUIRED_AD_GROUP env var.
        admin_list: List of admin user IDs. If None, uses RLS_ADMINS env var.

    Example — Dash:
        app = dash.Dash(__name__)
        server = app.server
        enforce_access(server)

    Example — Dash with custom group:
        enforce_access(server, group_name='MY_TEAM_GROUP', admin_list=['l034698'])

    Example — Flask:
        app = Flask(__name__)
        enforce_access(app)
    """
    from flask import Response

    _group = group_name or REQUIRED_AD_GROUP
    _admins = [x.lower() for x in (admin_list or RLS_ADMINS)]

    @server_app.before_request
    def _check_ad_access():
        from flask import request

        creds = request.headers.get("RStudio-Connect-Credentials", "")
        if not creds:
            return  # Local development

        try:
            user_id = json.loads(creds).get("user", "")
        except Exception:
            return

        # Admins always allowed
        if user_id.lower() in _admins:
            return

        # No group configured = allow all
        if not _group:
            return

        # Check AD group (cached)
        if check_ad_group(user_id, _group):
            return

        # Denied
        html = ACCESS_DENIED_HTML.format(group_name=_group)
        return Response(html, status=403, content_type="text/html")


# ═════════════════════════════════════════════════════════════════════
#  UTILITY FUNCTIONS
# ═════════════════════════════════════════════════════════════════════

def get_user_info(user_id=None):
    """Get comprehensive user information.

    Returns a dictionary with all available user details.

    Args:
        user_id: Optional user ID. If None, uses current authenticated user.

    Returns:
        dict: User information including id, name, admin status, groups.

    Example:
        info = get_user_info()
        print(info)
        # {'user_id': 'l034698', 'display_name': 'Giridhar S',
        #  'is_admin': True, 'groups': ['CARK00001', ...]}
    """
    if user_id is None:
        user_id = get_current_user()
    return {
        "user_id": user_id,
        "display_name": get_user_display_name(user_id),
        "is_admin": is_admin(user_id),
        "groups": get_user_groups(user_id),
        "in_required_group": check_ad_group(user_id) if REQUIRED_AD_GROUP else None,
    }


def clear_caches():
    """Clear all cached AD data. Useful after configuration changes."""
    _auth_cache.clear()
    _name_cache.clear()
    _groups_cache.clear()


def print_user_debug(user_id=None):
    """Print debug information about a user. Run in terminal for troubleshooting.

    Example:
        python -c "from ad_access import print_user_debug; print_user_debug('l034698')"
    """
    if user_id is None:
        user_id = _FALLBACK_USER
    info = get_user_info(user_id)
    print(f"User ID:        {info['user_id']}")
    print(f"Display Name:   {info['display_name']}")
    print(f"Is Admin:       {info['is_admin']}")
    print(f"In Required Group: {info['in_required_group']}")
    print(f"RLS_ADMINS:     {RLS_ADMINS}")
    print(f"REQUIRED_AD_GROUP: {REQUIRED_AD_GROUP}")
    print(f"Total Groups:   {len(info['groups'])}")
    if info['groups']:
        print(f"Groups (first 20):")
        for g in info['groups'][:20]:
            print(f"  - {g}")
