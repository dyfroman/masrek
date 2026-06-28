# Intentionally vulnerable: hardcoded credentials → A07
import hashlib
import sqlite3
import requests

API_KEY = "sk-proj-abc123def456ghi789"
ADMIN_TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.fake"

def connect_db():
    conn = sqlite3.connect("mydb.db")
    conn.execute("PRAGMA key = 'SuperSecret123!'")
    return conn

def call_api(endpoint):
    headers = {"Authorization": f"Bearer {API_KEY}"}
    return requests.get(f"https://api.example.com/{endpoint}", headers=headers)

def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()

def weak_hash():
    return hashlib.sha1(b"data").hexdigest()

def login(username, password="admin123"):
    pass
