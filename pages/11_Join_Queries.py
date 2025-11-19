import streamlit as st
import pandas as pd
from db import get_connection

st.header("JOIN Operations")

join_type = st.selectbox(
    "Select JOIN Type",
    ["INNER JOIN", "LEFT JOIN", "RIGHT JOIN", "Multiple JOINs"]
)

conn = get_connection()
cursor = conn.cursor()

if join_type == "INNER JOIN":
    st.subheader("INNER JOIN - Assets with Vulnerabilities")
    st.info("Returns only assets that have vulnerabilities in VULNERABILITY.")
    st.code("""
SELECT a.name AS Asset, a.type AS Type, v.cve_id AS CVE, v.severity AS Severity
FROM ASSET a
INNER JOIN VULNERABILITY v ON a.asset_id = v.asset_id;
    """, language="sql")
    cursor.execute("""
        SELECT a.name AS Asset, a.type AS Type, v.cve_id AS CVE, v.severity AS Severity
        FROM ASSET a
        INNER JOIN VULNERABILITY v ON a.asset_id = v.asset_id;
    """)
    df = pd.DataFrame(cursor.fetchall())
    st.dataframe(df, use_container_width=True)

elif join_type == "LEFT JOIN":
    st.subheader("LEFT JOIN - All Assets with Optional Vulnerabilities")
    st.info("Returns all assets; vulnerability fields are NULL when no match.")
    st.code("""
SELECT a.name AS Asset, a.type AS Type, a.ip AS IP, v.cve_id AS CVE, v.severity AS Severity
FROM ASSET a
LEFT JOIN VULNERABILITY v ON a.asset_id = v.asset_id;
    """, language="sql")
    cursor.execute("""
        SELECT a.name AS Asset, a.type AS Type, a.ip AS IP, v.cve_id AS CVE, v.severity AS Severity
        FROM ASSET a
        LEFT JOIN VULNERABILITY v ON a.asset_id = v.asset_id;
    """)
    df = pd.DataFrame(cursor.fetchall())
    st.dataframe(df, use_container_width=True)

elif join_type == "RIGHT JOIN":
    st.subheader("RIGHT JOIN - All Vulnerabilities with Assets (if any)")
    st.info("Returns all vulnerabilities; asset fields are NULL if asset is missing.")
    st.code("""
SELECT a.name AS Asset, a.type AS Type, v.cve_id AS CVE, v.severity AS Severity
FROM ASSET a
RIGHT JOIN VULNERABILITY v ON a.asset_id = v.asset_id;
    """, language="sql")
    cursor.execute("""
        SELECT a.name AS Asset, a.type AS Type, v.cve_id AS CVE, v.severity AS Severity
        FROM ASSET a
        RIGHT JOIN VULNERABILITY v ON a.asset_id = v.asset_id;
    """)
    df = pd.DataFrame(cursor.fetchall())
    st.dataframe(df, use_container_width=True)

elif join_type == "Multiple JOINs":
    st.subheader("Multiple JOINs - Complete Security View")
    st.info("ASSET → VULNERABILITY → PATCH → PATCH_DEPLOYMENT (via patch_id)")
    st.code("""
SELECT 
  a.name AS Asset,
  v.cve_id AS CVE,
  v.severity AS Severity,
  p.patch_version AS Patch,
  p.release_date AS Release_Date,
  pd.status AS Deployment_Status
FROM ASSET a
LEFT JOIN VULNERABILITY v ON a.asset_id = v.asset_id
LEFT JOIN PATCH p ON v.vuln_id = p.vuln_id
LEFT JOIN PATCH_DEPLOYMENT pd ON p.patch_id = pd.patch_id
ORDER BY a.name, v.cve_id;
    """, language="sql")
    cursor.execute("""
        SELECT 
          a.name AS Asset,
          v.cve_id AS CVE,
          v.severity AS Severity,
          p.patch_version AS Patch,
          p.release_date AS Release_Date,
          pd.status AS Deployment_Status
        FROM ASSET a
        LEFT JOIN VULNERABILITY v ON a.asset_id = v.asset_id
        LEFT JOIN PATCH p ON v.vuln_id = p.vuln_id
        LEFT JOIN PATCH_DEPLOYMENT pd ON p.patch_id = pd.patch_id
        ORDER BY a.name, v.cve_id;
    """)
    df = pd.DataFrame(cursor.fetchall())
    st.dataframe(df, use_container_width=True)

conn.close()
