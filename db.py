import pymysql
import streamlit as st
import pandas as pd

def get_connection():
    return pymysql.connect(
        host="localhost",
        user="root",
        password="asdf;lkj",   # put your MySQL password here
        database="asi",
        cursorclass=pymysql.cursors.DictCursor
    )

def run_query(query, params=None, fetch=True):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(query, params or ())
    data = cur.fetchall() if fetch else None
    conn.commit()
    cur.close()
    conn.close()
    return data
