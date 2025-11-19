import streamlit as st
import pandas as pd
from db import run_query

st.header("Exposure Table")

data = run_query("SELECT * FROM EXPOSURE")
st.dataframe(pd.DataFrame(data))

st.subheader("Add Exposure")
with st.form("add_exposure"):
    asset_id = st.number_input("Asset ID", step=1)
    port = st.number_input("Port", step=1)
    service = st.text_input("Service")
    if st.form_submit_button("Add"):
        run_query("INSERT INTO EXPOSURE (asset_id, port, service) VALUES (%s,%s,%s)",
                  (asset_id, port, service), fetch=False)
        st.success("Added!")
         

st.subheader("Edit / Delete Exposure")
ids = [str(r["exposure_id"]) for r in data]
selected = st.selectbox("Select Exposure ID", ids)
if selected:
    row = next(r for r in data if str(r["exposure_id"]) == selected)
    asset_id = st.number_input("Asset ID", value=row["asset_id"], step=1)
    port = st.number_input("Port", value=row["port"], step=1)
    service = st.text_input("Service", row["service"])

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Update"):
            run_query("UPDATE EXPOSURE SET asset_id=%s, port=%s, service=%s WHERE exposure_id=%s",
                      (asset_id, port, service, selected), fetch=False)
            st.success("Updated!")
             
    with col2:
        if st.button("Delete"):
            run_query("DELETE FROM EXPOSURE WHERE exposure_id=%s", (selected,), fetch=False)
            st.warning("Deleted!")
             
