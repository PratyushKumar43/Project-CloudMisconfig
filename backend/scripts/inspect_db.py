import sqlite3
import json
from datetime import datetime

def print_table_info(cursor, table_name):
    print(f"\n=== Table: {table_name} ===")
    # Get column info
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = cursor.fetchall()
    print("\nColumns:")
    for col in columns:
        print(f"  {col[1]} ({col[2]})")
    
    # Get row count
    cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
    count = cursor.fetchone()[0]
    print(f"\nTotal rows: {count}")
    
    # Show sample data if exists
    if count > 0:
        cursor.execute(f"SELECT * FROM {table_name} LIMIT 3")
        rows = cursor.fetchall()
        print("\nSample data:")
        for row in rows:
            print(f"  {row}")

def main():
    conn = sqlite3.connect('aws_config.db')
    cursor = conn.cursor()
    
    # Get list of tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = cursor.fetchall()
    
    print("Database Tables:")
    for table in tables:
        table_name = table[0]
        print_table_info(cursor, table_name)
    
    conn.close()

if __name__ == "__main__":
    main()
