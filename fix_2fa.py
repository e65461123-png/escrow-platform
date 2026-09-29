from urllib.parse import urlparse
import pg8000.dbapi

url = "postgresql://neondb_owner:npg_c3CAw9leXvGU@ep-orange-band-b33i5qb0-pooler.c-4.ap-southeast-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require"

p = urlparse(url)
conn = pg8000.dbapi.connect(
    user=p.username, password=p.password,
    host=p.hostname, port=p.port or 5432,
    database=p.path[1:]
)
cur = conn.cursor()

cmds = [
    'ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret TEXT',
    'ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled INTEGER DEFAULT 0',
    'ALTER TABLE users ADD COLUMN IF NOT EXISTS backup_codes TEXT',
]

for cmd in cmds:
    try:
        cur.execute(cmd)
        print(f'OK: {cmd[:60]}')
    except Exception as e:
        print(f'ERR: {e}')

conn.commit()
conn.close()
print('DONE')
