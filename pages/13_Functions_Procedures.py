import streamlit as st
import pandas as pd
from db import run_query

st.title("Stored Functions and Procedures")

st.markdown("""
This page demonstrates execution of predefined **stored procedures** and **functions** 
used in the ASI Security Management System.
""")

# --- SECTION 1: Stored Procedures ---
st.header("Stored Procedures")

procedure = st.selectbox(
    "Select a procedure to run",
    ["sp_get_critical_vulns", "sp_get_assets_by_provider"]
)

if procedure == "sp_get_critical_vulns":
    st.subheader("Procedure: sp_get_critical_vulns()")
    st.code("""
CREATE PROCEDURE sp_get_critical_vulns()
BEGIN
    SELECT * FROM VULNERABILITY
    WHERE severity = 'Critical';
END;
    """, language="sql")

    if st.button("Run Procedure"):
        rows = run_query("CALL sp_get_critical_vulns();")
        if rows:
            st.dataframe(pd.DataFrame(rows))
        else:
            st.info("No data returned.")

elif procedure == "sp_get_assets_by_provider":
    st.subheader("Procedure: sp_get_assets_by_provider(IN provider_name VARCHAR(50))")
    st.code("""
CREATE PROCEDURE sp_get_assets_by_provider(IN provider_name VARCHAR(50))
BEGIN
    SELECT a.*
    FROM ASSET a
    JOIN CLOUD_ACCOUNT ca ON a.account_id = ca.account_id
    WHERE ca.provider = provider_name;
END;
    """, language="sql")

    provider = st.text_input("Enter provider name (e.g., AWS, Azure, Google Cloud)")
    if st.button("Run Procedure"):
        if provider.strip():
            rows = run_query(f"CALL sp_get_assets_by_provider('{provider}');")
            if rows:
                st.dataframe(pd.DataFrame(rows))
            else:
                st.info("No matching records found.")
        else:
            st.warning("Please enter a provider name.")


st.divider()

# --- SECTION 2: Stored Functions ---
st.header("Stored Functions")

function = st.selectbox(
    "Select a function to run",
    ["fn_total_vulnerabilities", "fn_get_asset_name"]
)

if function == "fn_total_vulnerabilities":
    st.subheader("Function: fn_total_vulnerabilities()")
    st.code("""
CREATE FUNCTION fn_total_vulnerabilities()
RETURNS INT
DETERMINISTIC
BEGIN
    DECLARE total INT;
    SELECT COUNT(*) INTO total FROM VULNERABILITY;
    RETURN total;
END;
    """, language="sql")

    if st.button("Run Function"):
        rows = run_query("SELECT fn_total_vulnerabilities() AS total;")
        st.metric("Total Vulnerabilities", rows[0]['total'])

elif function == "fn_get_asset_name":
    st.subheader("Function: fn_get_asset_name(p_asset_id INT)")
    st.code("""
CREATE FUNCTION fn_get_asset_name(p_asset_id INT)
RETURNS VARCHAR(100)
DETERMINISTIC
BEGIN
    DECLARE asset_name VARCHAR(100);
    SELECT name INTO asset_name FROM ASSET WHERE asset_id = p_asset_id;
    RETURN asset_name;
END;
    """, language="sql")

    asset_id = st.number_input("Enter Asset ID", min_value=1, step=1)
    if st.button("Run Function"):
        rows = run_query(f"SELECT fn_get_asset_name({asset_id}) AS asset_name;")
        st.success(f"Asset Name: {rows[0]['asset_name']}")
