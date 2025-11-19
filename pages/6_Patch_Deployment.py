# pages/6_Patch_Deployment.py
import streamlit as st
import pandas as pd
from db import run_query

st.header("Patch Deployment Table")

# View table (simple)
data = run_query("SELECT deploy_id, patch_id, status, deployed_at FROM PATCH_DEPLOYMENT ORDER BY deploy_id DESC")
st.dataframe(pd.DataFrame(data))

st.subheader("Add Patch Deployment")
with st.form("add_deploy"):
    patch_id = st.number_input("Patch ID", step=1, min_value=1)
    status = st.selectbox("Status", ["Pending", "In Progress", "Completed", "Failed"])
    if st.form_submit_button("Add"):
        run_query(
            "INSERT INTO PATCH_DEPLOYMENT (patch_id, status) VALUES (%s, %s)",
            (patch_id, status),
            fetch=False
        )
        st.success("Added!")
         

st.subheader("Edit / Delete Deployment")
ids = [str(r["deploy_id"]) for r in data]
selected = st.selectbox("Select Deployment ID", ids)
if selected:
    row = next(r for r in data if str(r["deploy_id"]) == selected)

    patch_id = st.number_input("Patch ID", value=row["patch_id"], step=1, min_value=1)
    status_options = ["Pending", "In Progress", "Completed", "Failed"]
    status = st.selectbox("Status", status_options, index=status_options.index(row["status"]))

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Update"):
            run_query(
                "UPDATE PATCH_DEPLOYMENT SET patch_id=%s, status=%s WHERE deploy_id=%s",
                (patch_id, status, selected),
                fetch=False
            )
            st.success("Updated!")
             
    with col2:
        if st.button("Delete"):
            run_query(
                "DELETE FROM PATCH_DEPLOYMENT WHERE deploy_id=%s",
                (selected,),
                fetch=False
            )
            st.warning("Deleted!")
             

st.caption("Note: deployed_at is set automatically by the database.")
