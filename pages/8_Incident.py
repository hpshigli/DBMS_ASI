import streamlit as st
import pandas as pd
from db import run_query

st.header("Incident Table")

data = run_query("SELECT * FROM INCIDENT")
st.dataframe(pd.DataFrame(data))

st.subheader("Add Incident")
with st.form("add_incident"):
    alert_id = st.number_input("Alert ID", step=1)
    classification = st.selectbox("Classification", ["Security Breach","Data Loss","Service Disruption","Policy Violation"])
    status = st.selectbox("Status", ["Open","In Progress","Resolved","Closed"])
    if st.form_submit_button("Add"):
        run_query("INSERT INTO INCIDENT (alert_id, classification, status) VALUES (%s,%s,%s)",
                  (alert_id, classification, status), fetch=False)
        st.success("Added!")
         

st.subheader("Edit / Delete Incident")
ids = [str(r["incident_id"]) for r in data]
selected = st.selectbox("Select Incident ID", ids)
if selected:
    row = next(r for r in data if str(r["incident_id"]) == selected)
    alert_id = st.number_input("Alert ID", value=row["alert_id"], step=1)
    classification = st.selectbox("Classification", ["Security Breach","Data Loss","Service Disruption","Policy Violation"],
                                  index=["Security Breach","Data Loss","Service Disruption","Policy Violation"].index(row["classification"]))
    status = st.selectbox("Status", ["Open","In Progress","Resolved","Closed"],
                          index=["Open","In Progress","Resolved","Closed"].index(row["status"]))

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Update"):
            run_query("UPDATE INCIDENT SET alert_id=%s, classification=%s, status=%s WHERE incident_id=%s",
                      (alert_id, classification, status, selected), fetch=False)
            st.success("Updated!")
             
    with col2:
        if st.button("Delete"):
            run_query("DELETE FROM INCIDENT WHERE incident_id=%s", (selected,), fetch=False)
            st.warning("Deleted!")
             
