# Intentionally vulnerable: insecure design patterns → A06 (partial)
import os
import pickle

def run_user_code(user_input):
    # eval of user input — classic insecure design
    return eval(user_input)

def execute_command(cmd):
    # os.system with user-controlled input
    os.system(cmd)

def deserialize_data(raw_bytes):
    # unsafe deserialization
    return pickle.loads(raw_bytes)
