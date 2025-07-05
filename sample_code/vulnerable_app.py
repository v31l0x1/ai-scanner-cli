import sqlite3
import hashlib
import os

# This is a sample file with intentional security and quality issues
# for testing the AI code scanner

class UserManager:
    def __init__(self, db_path):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        
    def create_user(self, username, password, email):
        # Security Issue: SQL Injection vulnerability
        query = f"INSERT INTO users (username, password, email) VALUES ('{username}', '{password}', '{email}')"
        self.conn.execute(query)
        self.conn.commit()
        
    def authenticate_user(self, username, password):
        # Security Issue: SQL Injection vulnerability
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        cursor = self.conn.execute(query)
        return cursor.fetchone()
    
    def get_user_by_id(self, user_id):
        # Security Issue: SQL Injection vulnerability
        query = f"SELECT * FROM users WHERE id = {user_id}"
        return self.conn.execute(query).fetchone()
    
    def hash_password(self, password):
        # Security Issue: Weak hashing algorithm
        return hashlib.md5(password.encode()).hexdigest()
    
    def generate_session_token(self):
        # Security Issue: Weak random number generation
        import random
        return str(random.randint(100000, 999999))

class FileHandler:
    def __init__(self, base_path):
        self.base_path = base_path
        
    def read_file(self, filename):
        # Security Issue: Path traversal vulnerability
        file_path = self.base_path + "/" + filename
        with open(file_path, 'r') as f:
            return f.read()
    
    def write_file(self, filename, content):
        # Security Issue: Path traversal vulnerability
        file_path = self.base_path + "/" + filename
        with open(file_path, 'w') as f:
            f.write(content)

# Quality Issues
def processData(data):  # Poor naming convention
    result = []
    for i in range(len(data)):  # Inefficient loop
        if data[i] != None:  # Should use 'is not None'
            result.append(data[i] * 2)  # Magic number
    return result

def duplicateCode1():
    # Duplicate code block
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    results = cursor.fetchall()
    conn.close()
    return results

def duplicateCode2():
    # Duplicate code block
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products")
    results = cursor.fetchall()
    conn.close()
    return results

# Performance Issues
def inefficient_search(items, target):
    # Performance Issue: Inefficient search algorithm
    for i in range(len(items)):
        for j in range(len(items)):
            if items[i] == target:
                return i
    return -1

def memory_leak_example():
    # Performance Issue: Potential memory leak
    large_list = []
    for i in range(1000000):
        large_list.append(i)
    # List is never cleared or used

# Hard-coded secrets
API_KEY = "sk-1234567890abcdef"  # Security Issue: Hardcoded secret
DATABASE_PASSWORD = "admin123"   # Security Issue: Hardcoded password

# Global variables (quality issue)
global_counter = 0
global_data = []

def main():
    # Missing error handling
    user_manager = UserManager("users.db")
    user_manager.create_user("admin", "password", "admin@example.com")
    
    # Missing input validation
    file_handler = FileHandler("/tmp")
    content = file_handler.read_file("../../../etc/passwd")
    
    print("Application started")
