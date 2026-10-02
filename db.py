import os
import asyncpg

async def init_db():
    pool = await asyncpg.create_pool(os.getenv("DATABASE_URL"), min_size=1, max_size=3)
    await pool.execute("""
        CREATE TABLE IF NOT EXISTS messages_unread (
            id TEXT PRIMARY KEY,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            text TEXT NOT NULL,
            created_at BIGINT NOT NULL,
            status TEXT NOT NULL DEFAULT 'sent'
        );
    """)
    await pool.execute("""
        CREATE INDEX IF NOT EXISTS idx_receiver ON messages_unread(receiver);
    """)
    return pool

async def write_message_db(pool, mid, meta, text):
    await pool.execute("""
        INSERT INTO messages_unread (id, sender, receiver, text, created_at, status)
        VALUES ($1, $2, $3, $4, $5, $6)
    """, mid, meta["sender"], meta["receiver"], text, meta["created_at"], meta["status"])
