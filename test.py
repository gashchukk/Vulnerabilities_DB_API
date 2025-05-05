import psycopg2
import json

# Database connection parameters
conn = psycopg2.connect(
    host="localhost",
    port=5432,
    user="postgres",
    password="test123",
    dbname="cve_db"
)

cur = conn.cursor()
cur.execute("SELECT * FROM cve_lookup")
rows = cur.fetchall()

# Convert to list of dictionaries
columns = [desc[0] for desc in cur.description]
data = [dict(zip(columns, row)) for row in rows]

# Write to JSON file
with open("output.json", "w") as f:
    json.dump(data, f, indent=4)

cur.close()
conn.close()
