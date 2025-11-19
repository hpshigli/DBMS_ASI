import streamlit as st
import pandas as pd
from db import get_connection

st.header("Nested Queries (Subqueries)")

choice = st.selectbox(
    "Choose Nested Query",
    [
        "Assets with Critical Vulnerabilities (IN)",
        "Assets Above Average Exposures (HAVING)",
        "Providers with Unpatched Critical Vulnerabilities (EXISTS)",
        "Top 3 Assets by Alert Count"
    ]
)

conn = get_connection()
cursor = conn.cursor()

if choice == "Assets with Critical Vulnerabilities (IN)":
    st.subheader("Assets with Critical Vulnerabilities")
    st.code("""
SELECT name AS Asset, type AS Type, ip AS IP
FROM ASSET
WHERE asset_id IN (
  SELECT asset_id FROM VULNERABILITY WHERE severity='Critical'
);
    """, language="sql")
    cursor.execute("""
        SELECT name AS Asset, type AS Type, ip AS IP
        FROM ASSET
        WHERE asset_id IN (
          SELECT asset_id FROM VULNERABILITY WHERE severity='Critical'
        );
    """)
    df = pd.DataFrame(cursor.fetchall())
    st.dataframe(df, use_container_width=True)

elif choice == "Assets Above Average Exposures (HAVING)":
    st.subheader("Assets with Above-Average Exposure Count")
    st.code("""
SELECT a.name AS Asset, COUNT(e.exposure_id) AS Exposure_Count
FROM ASSET a
JOIN EXPOSURE e ON a.asset_id = e.asset_id
GROUP BY a.asset_id, a.name
HAVING COUNT(e.exposure_id) > (
  SELECT AVG(cnt)
  FROM (SELECT COUNT(*) AS cnt FROM EXPOSURE GROUP BY asset_id) x
);
    """, language="sql")
    cursor.execute("""
        SELECT a.name AS Asset, COUNT(e.exposure_id) AS Exposure_Count
        FROM ASSET a
        JOIN EXPOSURE e ON a.asset_id = e.asset_id
        GROUP BY a.asset_id, a.name
        HAVING COUNT(e.exposure_id) > (
          SELECT AVG(cnt)
          FROM (SELECT COUNT(*) AS cnt FROM EXPOSURE GROUP BY asset_id) x
        );
    """)
    df = pd.DataFrame(cursor.fetchall())
    st.dataframe(df, use_container_width=True)

elif choice == "Providers with Unpatched Critical Vulnerabilities (EXISTS)":
    st.subheader("Providers with Unpatched Critical Vulnerabilities")
    st.code("""
SELECT DISTINCT ca.provider AS Provider, ca.account_name AS Account
FROM CLOUD_ACCOUNT ca
WHERE EXISTS (
  SELECT 1
  FROM ASSET a
  JOIN VULNERABILITY v ON a.asset_id = v.asset_id
  JOIN PATCH p ON v.vuln_id = p.vuln_id
  LEFT JOIN PATCH_DEPLOYMENT pd ON p.patch_id = pd.patch_id
  WHERE a.account_id = ca.account_id
    AND v.severity='Critical'
    AND (pd.status!='Completed' OR pd.status IS NULL)
);
    """, language="sql")
    cursor.execute("""
        SELECT DISTINCT ca.provider AS Provider, ca.account_name AS Account
        FROM CLOUD_ACCOUNT ca
        WHERE EXISTS (
          SELECT 1
          FROM ASSET a
          JOIN VULNERABILITY v ON a.asset_id = v.asset_id
          JOIN PATCH p ON v.vuln_id = p.vuln_id
          LEFT JOIN PATCH_DEPLOYMENT pd ON p.patch_id = pd.patch_id
          WHERE a.account_id = ca.account_id
            AND v.severity='Critical'
            AND (pd.status!='Completed' OR pd.status IS NULL)
        );
    """)
    df = pd.DataFrame(cursor.fetchall())
    st.dataframe(df, use_container_width=True)

elif choice == "Top 3 Assets by Alert Count":
    st.subheader("Top 3 Assets by Number of Alerts")
    st.code("""
SELECT a.name AS Asset, COUNT(al.alert_id) AS Alert_Count
FROM ASSET a
JOIN ALERT al ON a.asset_id = al.asset_id
GROUP BY a.asset_id, a.name
ORDER BY Alert_Count DESC
LIMIT 3;
    """, language="sql")
    cursor.execute("""
        SELECT a.name AS Asset, COUNT(al.alert_id) AS Alert_Count
        FROM ASSET a
        JOIN ALERT al ON a.asset_id = al.asset_id
        GROUP BY a.asset_id, a.name
        ORDER BY Alert_Count DESC
        LIMIT 3;
    """)
    df = pd.DataFrame(cursor.fetchall())
    st.dataframe(df, use_container_width=True)

conn.close()
