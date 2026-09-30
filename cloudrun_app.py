"""Model Armor demo for Google Cloud Run.

Uses the service's Application Default Credentials. The project is fixed by the
GOOGLE_CLOUD_PROJECT_ID environment variable (falling back to the ADC project)
so visitors cannot point the service account at other projects.
"""

import os

import google.auth
import streamlit as st
from google.auth.exceptions import DefaultCredentialsError

from core import CLOUD_PLATFORM_SCOPE, GoogleAuth, run


def _application_default_credentials():
    # Loaded once per session; each session gets its own credentials object.
    if "adc" not in st.session_state:
        try:
            st.session_state.adc = google.auth.default(scopes=[CLOUD_PLATFORM_SCOPE])
        except DefaultCredentialsError:
            st.session_state.adc = (None, None)
    return st.session_state.adc


def auth_ui() -> GoogleAuth:
    credentials, adc_project = _application_default_credentials()
    project_id = os.getenv("GOOGLE_CLOUD_PROJECT_ID") or adc_project or ""
    st.text_input(
        "**Project ID**",
        value=project_id,
        disabled=True,
        help="Set by the GOOGLE_CLOUD_PROJECT_ID environment variable.",
    )

    problem = None
    if credentials is None:
        problem = "No Google Cloud Application Default Credentials were found."
    elif not project_id:
        problem = "Google Cloud project ID is not configured. Set GOOGLE_CLOUD_PROJECT_ID."
    return GoogleAuth(credentials=credentials, project_id=project_id, cache_key="adc", problem=problem)


run(auth_ui)
