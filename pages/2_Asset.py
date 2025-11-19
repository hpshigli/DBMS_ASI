import streamlit as st
import pandas as pd
from db import run_query

st.header("Asset Table")

data = run_query("SELECT * FROM ASSET")
st.dataframe(pd.DataFrame(data))

st.subheader("Add Asset")
with st.form("add_asset"):
    name = st.text_input("Name")
    type_ = st.text_input("Type")
    ip = st.text_input("IP Address")
    account_id = st.number_input("Account ID", step=1)
    if st.form_submit_button("Add"):
        run_query("INSERT INTO ASSET (name, type, ip, account_id) VALUES (%s,%s,%s,%s)",
                  (name, type_, ip, account_id), fetch=False)
        st.success("Asset added!")


st.subheader("Edit / Delete Asset")
ids = [str(r["asset_id"]) for r in data]
selected = st.selectbox("Select Asset ID", ids)
if selected:
    row = next(r for r in data if str(r["asset_id"]) == selected)
    name = st.text_input("Name", row["name"])
    type_ = st.text_input("Type", row["type"])
    ip = st.text_input("IP", row["ip"])
    account_id = st.number_input("Account ID", value=row["account_id"], step=1)

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Update"):
            run_query("UPDATE ASSET SET name=%s, type=%s, ip=%s, account_id=%s WHERE asset_id=%s",
                      (name, type_, ip, account_id, selected), fetch=False)
            st.success("Updated!")

    with col2:
        if st.button("Delete"):
            run_query("DELETE FROM ASSET WHERE asset_id=%s", (selected,), fetch=False)
            st.warning("Deleted!")

