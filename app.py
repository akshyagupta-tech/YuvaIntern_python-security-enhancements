import streamlit as st
from secure_auth_app import EnterpriseSecurityEngine
from vulnerable_auth_app import login_vulnerable, init_db as init_vuln_db

st.set_page_config(page_title="Week 5: Security Hardening", layout="centered")
st.title("🛡️ Week 5: OWASP Application Security Simulator")

init_vuln_db()
EnterpriseSecurityEngine.init_hardened_db()

st.subheader("Simulate SQL Injection Payload")
payload = st.text_input("Username / Exploit Payload:", "admin' --")
pwd = st.text_input("Password:", "any_password", type="password")

col1, col2 = st.columns(2)
with col1:
    st.error("Vulnerable Legacy Engine")
    if st.button("Test Insecure Auth"):
        res = login_vulnerable(payload, pwd)
        st.write("Result:", f"🚨 **BYPASS SUCCESSFUL! Role: {res}**" if res else "Failed")

with col2:
    st.success("Hardened Enterprise Engine")
    if st.button("Test Hardened Auth"):
        res = EnterpriseSecurityEngine.authenticate_user(payload, pwd)
        st.write("Result:", f"Authenticated: {res}" if res else "🛡️ **BLOCKED (Zero Bypass)**")
