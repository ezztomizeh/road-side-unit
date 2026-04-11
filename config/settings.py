# Road Side Unit (RSU) settings
RSU_HOST: str = "0.0.0.0"
RSU_PORT: int = 9999
RSU_ID: bytes = b"RSU-001"

# Protocol settings
PROTOCOL_VERSION: int = 0x1

# MASSEAGE TYPES
MSG_CLINET_HELLO: int = 0x01
MSG_SERVER_HELLO: int = 0x02
MSG_SESSION_CONFIRM: int = 0x03
MSG_DATA: int = 0x04

# Security settings
TIMESTAMP_WINDOW_MS: int = 10000  # 10 seconds

# REDIS settings
REDIS_HOST: str = "localhost"
REDIS_PORT: int = 6379
SESSION_TTL_SECONDS: int = 1800  # 30 minutes
CERT_CACHE_TTL_SECONDS: int = 300  # 5 minutes

# Backend API settings
BACKEND_BASE_URL = "http://127.0.0.1:8000"
BACKEND_API_KEY: str = "v2v_system_7013d0d99daae08789b2edc6ea231a11"

# Certificate settings
CA_CERT_PATH: str = "certs/ca_cert.pem"
CA_PRIVATE_KEY_PATH: str = "certs/ca_private_key.pem"
