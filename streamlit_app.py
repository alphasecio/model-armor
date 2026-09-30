"""Model Armor demo for running outside Google Cloud.

Each user uploads their own service account key. The key is parsed in memory,
kept only in that user's session, and never written to disk or the environment.
"""

import hashlib
import json
import os

import streamlit as st
from google.auth.exceptions import GoogleAuthError
from google.oauth2 import service_account

from core import CLOUD_PLATFORM_SCOPE, GoogleAuth, run


def _load_service_account(raw: bytes):
    """Return (credentials, project_id) for a service account key file, or raise ValueError."""
    info = json.loads(raw)
    if not isinstance(info, dict) or info.get("type") != "service_account":
        raise ValueError("not a service account key")
    credentials = service_account.Credentials.from_service_account_info(info, scopes=[CLOUD_PLATFORM_SCOPE])
    return credentials, info.get("project_id", "")


def auth_ui() -> GoogleAuth:
    creds_file = st.file_uploader("**Google Cloud credentials file**", type="json", max_upload_size=1)

    credentials, key_project, cache_key = None, "", ""
    if creds_file is None:
        st.session_state.pop("service_account", None)
    else:
        raw = creds_file.getvalue()
        cache_key = hashlib.sha256(raw).hexdigest()
        cached = st.session_state.get("service_account")
        if cached is None or cached[0] != cache_key:
            try:
                credentials, key_project = _load_service_account(raw)
                st.session_state.service_account = (cache_key, credentials, key_project)
            except (ValueError, GoogleAuthError):
                st.session_state.pop("service_account", None)
                st.error("That file is not a valid service account key.")
                cache_key = ""
        else:
            _, credentials, key_project = cached

    project_id = st.text_input("**Project ID**", value=os.getenv("GOOGLE_CLOUD_PROJECT_ID") or key_project).strip()

    problem = None
    if credentials is None:
        problem = "Please upload a Google Cloud service account key file."
    elif not project_id:
        problem = "Please provide the Google Cloud project ID."
    return GoogleAuth(credentials=credentials, project_id=project_id, cache_key=cache_key, problem=problem)


run(auth_ui)
