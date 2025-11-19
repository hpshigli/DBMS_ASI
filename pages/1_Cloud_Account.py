import streamlit as st
import pandas as pd
from db import run_query

st.header("Cloud Account Table")

data = run_query("SELECT * FROM CLOUD_ACCOUNT")
st.dataframe(pd.DataFrame(data))

st.subheader("Add Cloud Account")
with st.form("add_account"):
    provider = st.text_input("Provider")
    account_name = st.text_input("Account Name")
    submitted = st.form_submit_button("Add")
    if submitted:
        run_query("INSERT INTO CLOUD_ACCOUNT (provider, account_name) VALUES (%s,%s)", (provider, account_name), fetch=False)
        st.success("Added successfully!")


st.subheader("Edit / Delete Cloud Account")
ids = [str(r["account_id"]) for r in data]
selected = st.selectbox("Select account_id", ids)
if selected:
    row = next((r for r in data if str(r["account_id"])==selected), None)
    if row:
        provider = st.text_input("Provider", row["provider"])
        account_name = st.text_input("Account Name", row["account_name"])
        col1,col2 = st.columns(2)
        with col1:
            if st.button("Update"):
                run_query("UPDATE CLOUD_ACCOUNT SET provider=%s, account_name=%s WHERE account_id=%s",
                          (provider, account_name, selected), fetch=False)
                st.success("Updated!")

        with col2:
            if st.button("Delete"):
                run_query("DELETE FROM CLOUD_ACCOUNT WHERE account_id=%s", (selected,), fetch=False)
                st.warning("Deleted!")

