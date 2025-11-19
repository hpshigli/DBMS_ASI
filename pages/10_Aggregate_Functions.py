import streamlit as st
import pandas as pd
from db import get_connection

st.header("Aggregate Functions")

agg_query = st.selectbox(
    "Select Aggregate Query",
    [
        "Count Vulnerabilities by Severity",
        "Total Assets by Provider",
        "Average Exposures per Asset",
        "Count Incidents by Status",
        "Patches by Release Date"
    ]
)

conn = get_connection()
cursor = conn.cursor()

if agg_query == "Count Vulnerabilities by Severity":
    st.subheader("Vulnerabilities by Severity (COUNT + GROUP BY)")
    st.code("""
SELECT severity AS Severity, COUNT(*) AS Count
FROM VULNERABILITY
GROUP BY severity
ORDER BY Count DESC;
    """, language="sql")
    cursor.execute("""
        SELECT severity AS Severity, COUNT(*) AS Count
        FROM VULNERABILITY
        GROUP BY severity
        ORDER BY Count DESC;
    """)
    rows = cursor.fetchall()
    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True)
    if not df.empty:
        st.bar_chart(df.set_index("Severity"))

elif agg_query == "Total Assets by Provider":
    st.subheader("Assets per Provider (COUNT + JOIN + GROUP BY)")
    st.code("""
SELECT ca.provider AS Provider, COUNT(a.asset_id) AS Total_Assets
FROM CLOUD_ACCOUNT ca
LEFT JOIN ASSET a ON ca.account_id = a.account_id
GROUP BY ca.provider
ORDER BY Total_Assets DESC;
    """, language="sql")
    cursor.execute("""
        SELECT ca.provider AS Provider, COUNT(a.asset_id) AS Total_Assets
        FROM CLOUD_ACCOUNT ca
        LEFT JOIN ASSET a ON ca.account_id = a.account_id
        GROUP BY ca.provider
        ORDER BY Total_Assets DESC;
    """)
    df = pd.DataFrame(cursor.fetchall())
    st.dataframe(df, use_container_width=True)

elif agg_query == "Average Exposures per Asset":
    st.subheader("Average Exposures (AVG + Nested Query)")
    st.code("""
SELECT AVG(exposure_count) AS Avg_Exposures
FROM (
  SELECT asset_id, COUNT(*) AS exposure_count
  FROM EXPOSURE
  GROUP BY asset_id
) AS counts;
    """, language="sql")
    cursor.execute("""
        SELECT AVG(exposure_count) AS Avg_Exposures
        FROM (
          SELECT asset_id, COUNT(*) AS exposure_count
          FROM EXPOSURE
          GROUP BY asset_id
        ) AS counts;
    """)
    avg_val = cursor.fetchone()["Avg_Exposures"] or 0
    st.metric("Average Exposures per Asset", f"{avg_val:.2f}")

elif agg_query == "Count Incidents by Status":
    st.subheader("Incidents by Status (COUNT + GROUP BY + HAVING)")
    st.code("""
SELECT status AS Status, COUNT(*) AS Count
FROM INCIDENT
GROUP BY status
HAVING COUNT(*) > 0
ORDER BY Count DESC;
    """, language="sql")
    cursor.execute("""
        SELECT status AS Status, COUNT(*) AS Count
        FROM INCIDENT
        GROUP BY status
        HAVING COUNT(*) > 0
        ORDER BY Count DESC;
    """)
    df = pd.DataFrame(cursor.fetchall())
    st.dataframe(df, use_container_width=True)

elif agg_query == "Patches by Release Date":
    st.subheader("Patch Statistics (MIN, MAX, COUNT)")
    st.code("""
SELECT 
  COUNT(*) AS Total_Patches,
  MIN(release_date) AS First_Release,
  MAX(release_date) AS Latest_Release
FROM PATCH;
    """, language="sql")
    cursor.execute("""
        SELECT 
          COUNT(*) AS Total_Patches,
          MIN(release_date) AS First_Release,
          MAX(release_date) AS Latest_Release
        FROM PATCH;
    """)
    r = cursor.fetchone()
    total = r["Total_Patches"] or 0
    first = r["First_Release"]
    last  = r["Latest_Release"]
    c1, c2, c3 = st.columns(3)
    c1.metric("Total Patches", total)
    c2.metric("First Release", str(first) if first else "-")
    c3.metric("Latest Release", str(last) if last else "-")

conn.close()
