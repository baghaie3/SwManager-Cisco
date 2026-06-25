import sqlite3, json

DB = "switches.db"

with open("partial_backup.json", "r", encoding="utf-8") as f:
    data = json.load(f)

conn = sqlite3.connect(DB)
cursor = conn.cursor()

def upsert(table, row):
    cols = ", ".join(row.keys())
    placeholders = ", ".join(["?" for _ in row])
    update_clause = ", ".join([f"{col}=excluded.{col}" for col in row.keys()])

    query = f"""
        INSERT INTO {table} ({cols})
        VALUES ({placeholders})
        ON CONFLICT(id) DO UPDATE SET {update_clause}
    """

    cursor.execute(query, tuple(row.values()))

tables = ["switches", "locations", "jobs"]

for table in tables:
    print(f"Merging table: {table} ...")
    for row in data.get(table, []):
        upsert(table, row)

conn.commit()
conn.close()

print("Import (merge) completed successfully.")
