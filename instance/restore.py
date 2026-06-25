import sqlite3
import json

def import_all_tables(json_file="backup.json", db_path="switches.db"):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # خواندن داده‌ها از فایل JSON
    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    for table, rows in data.items():
        print(f"Restoring table: {table}")

        # گرفتن ستون‌های واقعی جدول در دیتابیس
        cursor.execute(f"PRAGMA table_info({table});")
        table_info = cursor.fetchall()
        db_columns = [col[1] for col in table_info]

        if not db_columns:
            print(f"WARNING: Table '{table}' does not exist in the new DB, skipping...")
            continue

        for row in rows:
            # فقط ستون‌هایی که در جدول جدید وجود دارند را نگه می‌داریم
            valid_row = {k: v for k, v in row.items() if k in db_columns}

            # ساخت کوئری Insert
            cols = ", ".join(valid_row.keys())
            placeholders = ", ".join(["?"] * len(valid_row))
            values = list(valid_row.values())

            sql = f"INSERT INTO {table} ({cols}) VALUES ({placeholders})"

            try:
                cursor.execute(sql, values)
            except Exception as e:
                print(f"Error inserting into {table}: {e}")
                continue

    conn.commit()
    conn.close()
    print("Restore completed successfully!")
    

# اجرا
import_all_tables("backup.json", "switches.db")
