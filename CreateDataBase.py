import sqlite3
conn = sqlite3.connect('sqldatabase.db')
cur = conn.cursor()
cur.execute("""CREATE TABLE "authorization" ("id" INTEGER NOT NULL UNIQUE, "login"	TEXT NOT NULL UNIQUE, "email" TEXT NOT NULL, "password" TEXT NOT NULL, "salt" TEXT NOT NULL, "admin" BOOLEAN NOT NULL DEFAULT 'FALSE', PRIMARY KEY("id" AUTOINCREMENT));""")
cur.execute("""CREATE TABLE "revoked_tokens" ("id" INTEGER NOT NULL, "jti"	TEXT NOT NULL, "created_at" DateTime NOT NULL, PRIMARY KEY("id"));""")
cur.execute("""CREATE TABLE "url" ("original_url" TEXT NOT NULL,"short_url" TEXT NOT NULL,"type"	TEXT NOT NULL, "user" TEXT NOT NULL, "count"	INTEGER NOT NULL DEFAULT 0);""")
conn.commit()