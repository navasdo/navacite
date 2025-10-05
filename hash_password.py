# hash_password.py
# A simple utility to generate a bcrypt password hash for manual database entry.

from flask import Flask
from flask_bcrypt import Bcrypt

# We need to create a Flask app context for bcrypt to work
app = Flask(__name__)
bcrypt = Bcrypt(app)

def generate_hash():
    """
    Prompts the user for a password and prints its bcrypt hash.
    """
    try:
        # Get the password from user input (it won't be shown on screen)
        import getpass
        plain_text_password = getpass.getpass(prompt="Enter the password to hash: ")

        if not plain_text_password:
            print("Password cannot be empty.")
            return

        # Generate the hash and decode it to a string for storing in the database
        hashed_password = bcrypt.generate_password_hash(plain_text_password).decode('utf-8')

        print("\n--- Password Hashing Complete ---")
        print("Copy the following hashed password and paste it into the 'password' column in your database:")
        print(f"\n{hashed_password}\n")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == '__main__':
    generate_hash()
