import sqlite3
c=sqlite3.connect("data/bugbounty.db")
seen=set()
for r in c.execute("SELECT method,url,status_code FROM requests WHERE url LIKE '%arc.io%' AND (url LIKE '%/api/%' OR url LIKE '%/v1/%' OR url LIKE '%/v2/%' OR url LIKE '%graphql%') ORDER BY id DESC LIMIT 80"):
    key=(r[0], r[1].split("?")[0])
    if key in seen: continue
    seen.add(key)
    print(r[2], r[0], r[1][:100])
