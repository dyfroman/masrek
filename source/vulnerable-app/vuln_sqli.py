# Intentionally vulnerable: SQL injection via string formatting → A05
import sqlite3

def get_user(username):
    conn = sqlite3.connect("users.db")
    query = f"SELECT * FROM users WHERE username = '{username}'"
    result = conn.execute(query)
    return result.fetchone()

def search_products(term):
    conn = sqlite3.connect("shop.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{term}%'")
    return cursor.fetchall()

def delete_user(user_id):
    conn = sqlite3.connect("users.db")
    conn.execute("DELETE FROM users WHERE id = '%s'" % user_id)
    conn.commit()
