import streamlit as st
import pandas as pd
from db import run_query

st.header("Alerts Table (auto-created by triggers)")

data = run_query("SELECT * FROM ALERT ORDER BY created_at DESC")
st.dataframe(pd.DataFrame(data))

st.info("Alerts are automatically generated when CRUD happens on Vulnerability, Exposure, Patch, or Patch_Deployment.")
