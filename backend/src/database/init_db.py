import sqlite3
import os
from pathlib import Path
from .config import get_database_settings

def init_database():
    settings = get_database_settings()
    db_path = Path(settings.DATABASE_URL.replace('sqlite:///', ''))
    
    # Create database directory if it doesn't exist
    db_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Read schema file
    schema_path = Path(__file__).parent / 'schema.sql'
    with open(schema_path, 'r') as f:
        schema = f.read()
    
    # Connect to database and create tables
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(schema)
        conn.commit()
        print(f"Database initialized at {db_path}")
    finally:
        conn.close()

if __name__ == "__main__":
    init_database()
