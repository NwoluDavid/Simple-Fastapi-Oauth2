import json
from pathlib import Path

# Define the path for the database JSON file
DB_FILE = Path("database.json")

# Initialize the database if it doesn't exist
if not DB_FILE.exists():
    with open(DB_FILE, "w") as f:
        json.dump({}, f)

def read_db() -> dict:
    """
    Read the JSON database and return it as a dictionary.
    """
    with open(DB_FILE, "r") as f:
        return json.load(f)

def write_db(data: dict):
    """
    Write the given dictionary to the JSON database.
    """
    with open(DB_FILE, "w") as f:
        json.dump(data, f, indent=4)
