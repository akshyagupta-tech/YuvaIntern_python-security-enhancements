"""Safe Streamlit lab for validating defensive security controls."""

from __future__ import annotations

import secrets
import tempfile
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

from audit import AuditLogger
from auth import AuthenticationService
from database import Database
from sanitizer import InputSanitizer
from security_checks import scan_project
from security_errors import InputValidationError, public_error
from sessions import Role
from vulnerable_auth_app import comparison_examples


def _security_context() -> dict[str, Any]:
    """Create an isolated per-browser demo database and random test account."""
    context = st.session_state.get("security_context")
    if context is not None:
        return context
    temp_directory = tempfile.TemporaryDirectory(prefix="week5-security-")
    database = Database(Path(temp_directory.name) / "demo.sqlite3")
    database.initialize()
    audit = AuditLogger()
    service = AuthenticationService(database, audit=audit)
    demo_username = "demo_operator"
    demo_password = secrets.token_urlsafe(20)
    service.register_user(demo_username, demo_password, Role.OPERATOR)
    context = {
        "temporary_directory": temp_directory,
        "database": database,
        "audit": audit,
        "service": service,
        "demo_username": demo_username,
        "demo_password": demo_password,
    }
    st.session_state["security_context"] = context
    return context


st.set_page_config(
    page_title="Enterprise Defensive Security & OWASP Hardening Suite",
    layout="wide",
)
st.title("Enterprise Defensive Security & OWASP Hardening Suite")
st.caption("Defensive controls lab")

context = _security_context()
service: AuthenticationService = context["service"]
audit: AuditLogger = context["audit"]
sanitizer = InputSanitizer()

comparison_tab, validation_tab, authentication_tab, audit_tab = st.tabs(
    ("Control comparison", "Input validation", "Authentication", "Audit trail")
)

with comparison_tab:
    st.subheader("Vulnerable design and hardened control")
    st.dataframe(
        comparison_examples(), use_container_width=True, hide_index=True
    )
    st.write(
        "The vulnerable examples are descriptive only. No injected SQL or shell "
        "command is executed by this lab."
    )

with validation_tab:
    text_column, hostname_column = st.columns(2)
    with text_column:
        raw_text = st.text_area(
            "Untrusted text", "<b>Ａlice</b><script>drop</script>"
        )
        if st.button("Sanitize text", key="sanitize_text"):
            try:
                sanitized = sanitizer.sanitize_text(raw_text)
            except InputValidationError as error:
                audit.log("input.rejected", details={"field": "text"})
                st.error(public_error(error)["message"])
            else:
                audit.log("input.sanitized", details={"field": "text"})
                st.code(
                    sanitized or "[empty after sanitation]", language="text"
                )
    with hostname_column:
        host_value = st.text_input(
            "Hostname or IP address", "127.0.0.1; whoami"
        )
        if st.button("Validate target only", key="validate_host"):
            try:
                validated_host = sanitizer.validate_hostname(host_value)
            except InputValidationError as error:
                audit.log("diagnostic.host_rejected")
                st.error(public_error(error)["message"])
            else:
                audit.log("diagnostic.host_validated")
                st.success(
                    f"Valid target: {validated_host}. No network request was made."
                )

with authentication_tab:
    st.subheader("Demo account")
    st.write(f"Username: `{context['demo_username']}`")
    st.write("A random password is generated in server-side session state.")
    if st.button("Run successful login", key="demo_login"):
        credentials = service.login(
            context["demo_username"],
            context["demo_password"],
            "127.0.0.1",
        )
        if credentials is None:
            st.error("Authentication was rejected.")
        else:
            session = service.sessions.validate(credentials.session_token)
            st.success(
                f"Authenticated with role {session.role.value}; "
                "the session token was not displayed."
            )
            st.write("CSRF token issued: yes")
    attempt_column, lockout_column = st.columns(2)
    with attempt_column:
        username = st.text_input("Username to test", "demo_operator")
        password = st.text_input("Password to test", type="password")
        if st.button("Authenticate", key="custom_login"):
            credentials = service.login(username, password, "192.0.2.10")
            if credentials is None:
                st.error("Authentication failed or was throttled.")
            else:
                st.success("Authentication succeeded.")
    with lockout_column:
        st.metric("PBKDF2 rounds", 100_000)
        st.metric("Salt entropy", "16 random bytes")
        st.metric("Session TTL", f"{service.sessions.ttl_seconds:.0f} seconds")

with audit_tab:
    st.subheader("Redacted, tamper-evident audit records")
    records = audit.records()
    st.metric("Integrity chain valid", "Yes" if audit.verify_chain() else "No")
    if records:
        st.dataframe(
            pd.DataFrame(records), use_container_width=True, hide_index=True
        )
    else:
        st.info(
            "No security events have been recorded in this browser session."
        )
    if st.button("Run static integrity scan", key="static_scan"):
        findings = scan_project(Path(__file__).resolve().parent)
        if findings:
            st.error(f"Found {len(findings)} security finding(s).")
            st.dataframe(
                [finding.to_dict() for finding in findings],
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.success("No prohibited patterns found in the project source.")
