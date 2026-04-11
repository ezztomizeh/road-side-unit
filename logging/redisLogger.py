import json
import redis

from config.settings import (
    REDIS_HOST,
    REDIS_PORT,
    SESSION_TTL_SECONDS,
    CERT_CACHE_TTL_SECONDS
)

class RedisLogger:
    def __init__(self):
        self.r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

    def get_cached_cert_status(self, cert_id: str):
        return self.r.get(f"cert:{cert_id}")
    
    def cache_cert_status(self, cert_id: str, status: str):
        self.r.setex(f"cert:{cert_id}", CERT_CACHE_TTL_SECONDS, status)

    def store_pending_handshake(self, handshake_id: int, data: dict):
        self.r.setex(f"pending:{handshake_id}", 120, json.dumps(data))

    def get_pending_handshake(self, handshake_id: int):
        raw = self.r.get(f"pending:{handshake_id}")
        return json.loads(raw) if raw else None
    
    def delete_pending_handshake(self, handshake_id: int):
        self.r.delete(f"pending:{handshake_id}")

    def store_session(self, session_id: int, session_key: bytes,
                      client_nonce: bytes, server_nonce: bytes):
        data = {
            "key": session_key.hex(),
            "last_seq": -1,
            "client_nonce": client_nonce.hex(),
            "server_nonce": server_nonce.hex()
        }
        self.r.setex(f"session:{session_id}", SESSION_TTL_SECONDS, json.dumps(data))

    def get_session(self, session_id: int):
        raw = self.r.get(f"session:{session_id}")
        return json.loads(raw) if raw else None
    
    def update_session_sequence(self, session_id: int, seq: int):
        session = self.get_session(session_id)
        if not session:
            return
        session["last_seq"] = seq
        self.r.setex(f"session:{session_id}", SESSION_TTL_SECONDS, json.dumps(session))