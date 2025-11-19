# pages/13_User_Management.py
import re
import streamlit as st
import pandas as pd
from db import get_connection, run_query

st.title("User & Privilege Management (MySQL)")

st.caption(
    "Requires a MySQL account with administrative privileges (CREATE USER / DROP USER / GRANT / REVOKE). "
    "All grants/revokes below are scoped to the current database, typically `asi`."
)

# ---------- Helpers ----------
def db_name():
    """Return current DB name from session_state or connection."""
    # try to use what's configured; fallback to 'asi'
    return st.session_state.get("db_name", "asi")

def sanitize_user(s: str) -> str:
    """Allow only alphanumerics and underscore in usernames to avoid injection via identifiers."""
    return re.sub(r"[^a-zA-Z0-9_]", "", s)

def sanitize_host(s: str) -> str:
    """Allow percent, dot, dash for host; strip anything else."""
    return re.sub(r"[^a-zA-Z0-9_%.:-]", "", s)

def exec_admin(sql: str, params=None, fetch=False):
    """Execute a single admin SQL statement with commit and error handling."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            rows = cur.fetchall() if fetch else None
        conn.commit()
        return rows, None
    except Exception as e:
        conn.rollback()
        return None, str(e)
    finally:
        conn.close()

def list_users():
    try:
        rows = run_query("SELECT user AS User, host AS Host FROM mysql.user ORDER BY user, host;")
        return pd.DataFrame(rows)
    except Exception as e:
        st.warning(f"Could not list users (need admin privileges): {e}")
        return pd.DataFrame()

def get_grants(user: str, host: str):
    # SHOW GRANTS returns multiple rows with a single column
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(f"SHOW GRANTS FOR `{user}`@'{host}';")
            rows = cur.fetchall()
        conn.commit()
        # rows are dicts like {'Grants for user@host': 'GRANT ...'}
        # Convert to a clean DataFrame
        grants = []
        for r in rows:
            grants.append(list(r.values())[0])
        return pd.DataFrame({"Grant": grants})
    except Exception as e:
        st.warning(f"Could not fetch grants for {user}@{host}: {e}")
        return pd.DataFrame()
    finally:
        conn.close()

schema = db_name()

# ---------- Section: List users & view grants ----------
st.header("Users & Grants")

users_df = list_users()
if users_df.empty:
    st.info("No users listed or insufficient privileges to read `mysql.user`.")
else:
    st.dataframe(users_df, use_container_width=True, hide_index=True)

    st.subheader("View Grants for a User")
    c1, c2 = st.columns(2)
    with c1:
        sel_user = st.text_input("User (e.g., app_user)", value=users_df.iloc[0]["User"] if not users_df.empty else "")
    with c2:
        sel_host = st.text_input("Host (e.g., %, localhost)", value=users_df.iloc[0]["Host"] if not users_df.empty else "%")

    if st.button("Show Grants"):
        if sel_user and sel_host:
            gdf = get_grants(sel_user, sel_host)
            if gdf.empty:
                st.info("No grants returned.")
            else:
                st.dataframe(gdf, use_container_width=True, hide_index=True)

st.divider()

# ---------- Section: Create user ----------
st.header("Create User")

with st.form("create_user_form"):
    cu1, cu2 = st.columns(2)
    with cu1:
        new_user = st.text_input("Username", placeholder="e.g., app_user")
        new_host = st.text_input("Host", value="%", help="Use '%' for any host, or 'localhost'")
    with cu2:
        new_password = st.text_input("Password", type="password")
        preset = st.selectbox(
            "Privilege Preset (on schema)",
            ["Read-only (SELECT)", "Read/Write (SELECT, INSERT, UPDATE, DELETE, EXECUTE)", "Admin (ALL on schema)", "None"]
        )

    submitted = st.form_submit_button("Create User")
    if submitted:
        u = sanitize_user(new_user)
        h = sanitize_host(new_host or "%")
        if not u or not new_password:
            st.error("Username and password are required.")
        else:
            # CREATE USER
            _, err = exec_admin(f"CREATE USER `{u}`@'{h}' IDENTIFIED BY %s;", (new_password,))
            if err:
                st.error(f"CREATE USER failed: {err}")
            else:
                st.success(f"User `{u}`@'{h}' created.")

                # Apply preset grants on this schema
                if preset.startswith("Read-only"):
                    _, err = exec_admin(f"GRANT SELECT ON `{schema}`.* TO `{u}`@'{h}';")
                elif preset.startswith("Read/Write"):
                    _, err = exec_admin(
                        f"GRANT SELECT, INSERT, UPDATE, DELETE, EXECUTE ON `{schema}`.* TO `{u}`@'{h}';"
                    )
                elif preset.startswith("Admin"):
                    _, err = exec_admin(f"GRANT ALL PRIVILEGES ON `{schema}`.* TO `{u}`@'{h}';")
                else:
                    err = None

                if err:
                    st.error(f"Grant failed: {err}")
                else:
                    # FLUSH PRIVILEGES is optional for GRANT/CREATE USER in MySQL 8, but harmless.
                    exec_admin("FLUSH PRIVILEGES;")
                    st.success(f"Preset '{preset}' applied on `{schema}`.*")
                    # refresh list
                    users_df = list_users()

st.divider()

# ---------- Section: Change password ----------
st.header("Change Password")

cp1, cp2, cp3 = st.columns(3)
with cp1:
    ch_user = st.text_input("User", key="pwd_user")
with cp2:
    ch_host = st.text_input("Host", value="%", key="pwd_host")
with cp3:
    ch_pass = st.text_input("New Password", type="password", key="pwd_pass")

if st.button("Update Password"):
    u = sanitize_user(ch_user)
    h = sanitize_host(ch_host or "%")
    if not u or not ch_pass:
        st.error("User and new password are required.")
    else:
        _, err = exec_admin(f"ALTER USER `{u}`@'{h}' IDENTIFIED BY %s;", (ch_pass,))
        if err:
            st.error(f"ALTER USER failed: {err}")
        else:
            exec_admin("FLUSH PRIVILEGES;")
            st.success(f"Password updated for `{u}`@'{h}'.")

st.divider()

# ---------- Section: Grant / Revoke privileges on current schema ----------
st.header(f"Grant / Revoke Privileges on `{schema}`.*")

gr1, gr2, gr3 = st.columns(3)
with gr1:
    gr_user = st.text_input("User", key="gr_user")
with gr2:
    gr_host = st.text_input("Host", value="%", key="gr_host")
with gr3:
    action = st.selectbox("Action", ["GRANT", "REVOKE"])

privs = st.multiselect(
    "Privileges",
    ["SELECT", "INSERT", "UPDATE", "DELETE", "EXECUTE", "CREATE", "DROP", "ALTER", "INDEX", "TRIGGER"],
    default=["SELECT"]
)

if st.button(f"{action} Selected Privileges"):
    u = sanitize_user(gr_user)
    h = sanitize_host(gr_host or "%")
    if not u or not privs:
        st.error("User and at least one privilege are required.")
    else:
        plist = ", ".join(privs)
        if action == "GRANT":
            _, err = exec_admin(f"GRANT {plist} ON `{schema}`.* TO `{u}`@'{h}';")
        else:
            _, err = exec_admin(f"REVOKE {plist} ON `{schema}`.* FROM `{u}`@'{h}';")
        if err:
            st.error(f"{action} failed: {err}")
        else:
            exec_admin("FLUSH PRIVILEGES;")
            st.success(f"{action} successful for `{u}`@'{h}` on `{schema}`.*")

st.divider()

# ---------- Section: Delete user ----------
st.header("Delete User")

du1, du2 = st.columns(2)
with du1:
    del_user = st.text_input("User", key="del_user")
with du2:
    del_host = st.text_input("Host", value="%", key="del_host")

if st.button("Drop User"):
    u = sanitize_user(del_user)
    h = sanitize_host(del_host or "%")
    if not u:
        st.error("User is required.")
    else:
        _, err = exec_admin(f"DROP USER `{u}`@'{h}';")
        if err:
            st.error(f"DROP USER failed: {err}")
        else:
            exec_admin("FLUSH PRIVILEGES;")
            st.success(f"User `{u}`@'{h}' dropped.")
            users_df = list_users()
