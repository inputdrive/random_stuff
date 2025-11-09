# attempt to fix path traversal in python as an example
# base_dir simplifies the code for obfuscation techniques
# hasn't been tested, initial idea 

import os
from pathlib import Path

def is_safe_path(base_dir, user_path):
    # Resolve the absolute path of the base directory and user input path
    base_dir = Path(base_dir).resolve()
    requested_path = (Path(base_dir) / user_path).resolve()

    # Check if requested_path starts with (is within) base_dir path
    return requested_path.is_relative_to(base_dir)

# Example usage:
base_directory = '/safe/base/dir'

user_input = '../../etc/passwd'  # Malicious attempt
if is_safe_path(base_directory, user_input):
    print("Safe to access:", os.path.join(base_directory, user_input))
else:
    print("Potential path traversal detected. Access denied.")
