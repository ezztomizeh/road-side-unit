import json
import redis

from config.settings import (
    REDIS_HOST,
    REDIS_PORT,
    SESSION_TTL_SECONDS,
    CERT_CACHE_TTL_SECONDS,
    TTL_DELETE_INTERVAL_SECONDS
)
import data

class RedisLogger:
    def __init__(self):
        self.r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
        self.__socket_logger = {}

    def get_cached_cert_status(self, cert_id: str):
        return self.r.get(f"cert:{cert_id}")
    
    def get_all_sessions(self):
        sessions = []
        for key in self.r.scan_iter(match="session:*"):
            if isinstance(key, bytes):
                key = key.decode()
            session_id = key.split(":")[-1]
            sessions.append(session_id)
        return sessions
    
    def log_socket(self, session_id: int, socket):
        self.__socket_logger[session_id] = socket
    
    def get_logged_socket(self, session_id: int):
        return self.__socket_logger.get(session_id,list())
    
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
            "rx_last_seq": -1,
            "tx_seq":0,
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

    def store_vehicle_intersection_data(self, obu_id: int, data: dict):
        key = f"vehicle:intersection:{obu_id}"
        self.r.setex(key, TTL_DELETE_INTERVAL_SECONDS, json.dumps(data))
        print(f"[+] Stored intersection data for OBU {obu_id} in Redis with key {key}")

    def get_vehicle_intersection_sessions(self):
        patterns = f"vehicle:intersection:*"
        sessions = []
        for key in self.r.scan_iter(match=patterns):
            if isinstance(key, bytes):
                key = key.decode()

            obu_id = key.split(":")[-1]
            sessions.append(obu_id)
        return sessions


    def get_all_intersection_vehicles(self):
        vehicles = []

        for key in self.r.scan_iter("vehicle:intersection:*"):
            raw = self.r.get(key)

            if not raw:
                continue

            try:
                data = json.loads(raw)
                vehicles.append(data)
            except json.JSONDecodeError:
                continue

        return vehicles
    
    def delete_vehicle_intersection_data(self, obu_id: str):
        self.r.delete(f"vehicle:intersection:{obu_id}")
    
    def update_rx_sequence(self, session_id: int, seq: int):
        session = self.get_session(session_id)
        if not session:
            return

        session["rx_last_seq"] = seq

        self.r.setex(
            f"session:{session_id}",
            SESSION_TTL_SECONDS,
            json.dumps(session)
        )


    def get_tx_sequence(self, session_id: int) -> int:
        session = self.get_session(session_id)
        if not session:
            raise ValueError("Session not found")

        return session.get("tx_seq", 0)


    def increment_tx_sequence(self, session_id: int):
        session = self.get_session(session_id)
        if not session:
            return

        session["tx_seq"] = session.get("tx_seq", 0) + 1

        self.r.setex(
            f"session:{session_id}",
            SESSION_TTL_SECONDS,
            json.dumps(session)
        )

    def store_street_data(self, session_id: str, street_name: str):
        key = f"street:{street_name}:{session_id}"
        self.r.setex(key, TTL_DELETE_INTERVAL_SECONDS, street_name)
        print(f"[+] Stored street data for street {street_name} in Redis with key {key}")

    def get_street_sessions(self, street_name: str):
        pattern = f"street:{street_name}:*"
        sessions = []

        for key in self.r.scan_iter(match=pattern):
            if isinstance(key, bytes):
                key = key.decode()

            session_id = key.split(":")[-1]
            sessions.append(session_id)

        return sessions
    
    def get_session_street(self, session_id: str):
        pattern = f"street:*:{session_id}"
        for key in self.r.scan_iter(match=pattern):
            if isinstance(key, bytes):
                key = key.decode()

            return self.r.get(key)

        return None