import streamlit as st
import pandas as pd
from db import run_query

st.header("Patch Table")

data = run_query("SELECT * FROM PATCH")
st.dataframe(pd.DataFrame(data))

st.subheader("Add Patch")
with st.form("add_patch"):
    vuln_id = st.number_input("Vulnerability ID", step=1)
    patch_version = st.text_input("Patch Version")
    release_date = st.date_input("Release Date")
    if st.form_submit_button("Add"):
        run_query("INSERT INTO PATCH (vuln_id, patch_version, release_date) VALUES (%s,%s,%s)",
                  (vuln_id, patch_version, release_date), fetch=False)
        st.success("Added!")
         

st.subheader("Edit / Delete Patch")
ids = [str(r["patch_id"]) for r in data]
selected = st.selectbox("Select Patch ID", ids)
if selected:
    row = next(r for r in data if str(r["patch_id"]) == selected)
    vuln_id = st.number_input("Vulnerability ID", value=row["vuln_id"], step=1)
    patch_version = st.text_input("Patch Version", row["patch_version"])
    release_date = st.date_input("Release Date", row["release_date"])

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Update"):
            run_query("UPDATE PATCH SET vuln_id=%s, patch_version=%s, release_date=%s WHERE patch_id=%s",
                      (vuln_id, patch_version, release_date, selected), fetch=False)
            st.success("Updated!")
             
    with col2:
        if st.button("Delete"):
            run_query("DELETE FROM PATCH WHERE patch_id=%s", (selected,), fetch=False)
            st.warning("Deleted!")
             
