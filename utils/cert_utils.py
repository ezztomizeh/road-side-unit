import hashlib
import requests
import time

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from config.settings import (
    BACKEND_API_KEY,
    BACKEND_BASE_URL,
    CA_CERT_PATH,
    CA_PRIVATE_KEY_PATH,
    RSU_ID,
    TIMESTAMP_WINDOW_MS
)
from log.redisLogger import RedisLogger

class CertificateManager:
    def __init__(self, redis_logger: RedisLogger) -> None:
        self.redis_logger = redis_logger

        with open(CA_CERT_PATH, "rb") as f:
            self.ca_cert = x509.load_pem_x509_certificate(f.read())

        with open(CA_PRIVATE_KEY_PATH, "rb") as f:
            self.ca_private_key = serialization.load_pem_private_key(f.read(), password=None)
        
        self.ca_public_key = self.ca_cert.public_key()

    def load_pem_certificate(self, pem_data: bytes) -> x509.Certificate:
        return x509.load_pem_x509_certificate(pem_data)
    
    def extract_public_key(self, cert: x509.Certificate):
        return cert.public_key()
    
    def extract_certificate_id(self, cert) -> str:
        return format(cert.serial_number, 'x')
    
    def verify_certificate_signature(self, cert: x509.Certificate) -> bool:
        try:
            self.ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm)
            )
            return True
        except Exception as e:
            return False
        
    def verify_certificate_time(self, cert) -> bool:
        current_time = time.time()
        not_before = cert.not_valid_before.timestamp()
        not_after = cert.not_valid_after.timestamp()
        return not_before <= current_time <= not_after
    
    def verify_timestamp(self, timestamp: int) -> bool:
        current_time_ms = int(time.time() * 1000)
        return abs(current_time_ms - timestamp) <= TIMESTAMP_WINDOW_MS
    
    def client_hello_hash(self, client_nonce: bytes, timestamp: int) -> bytes:
        m = hashlib.sha256()
        m.update(client_nonce)
        m.update(str(timestamp).encode())
        m.update(RSU_ID)
        return m.digest()
    
    def verify_raw_ecdsa_signature(self, public_key, data_hash: bytes,
                                     raw_signature: bytes) -> bool:
        try:
            if len(raw_signature) != 64:
                return False
            r = int.from_bytes(raw_signature[:32], byteorder='big')
            s = int.from_bytes(raw_signature[32:], byteorder='big')
            der_sig = encode_dss_signature(r, s)

            public_key.verify(
                der_sig,
                data_hash,
                ec.ECDSA(hashlib.sha256())
            )
            return True
        except Exception as e:
            return False
        
    def _headers(self):
        return {
            "X-API-Key": BACKEND_API_KEY
        }
    
    def verify_certificate_with_backend(self, cert_id: str) -> str:
        url = f"{BACKEND_BASE_URL}/api/v1/rsu/verify-certificate/{cert_id}"
        response = requests.get(url, headers=self._headers(), timeout=5)
        if "detail" in response.json():
            return "invalid"
        
        return response.json().get("status")
    
    def check_certificate_revocation(self, cert_id: str) -> bool:
        return False
    
    def check_cetificate_status(self, cert) -> bool:
        cert_id = self.extract_certificate_id(cert)

        cached = self.redis_logger.get_cached_cert_status(cert_id)
        if cached is not None:
            return cached == "valid"
        
        verify_result = self.verify_certificate_with_backend(cert_id)
        if not verify_result == "valid":
            return False

        rev_result = self.check_certificate_revocation(cert_id)
        if rev_result:
            return False
        
        self.redis_logger.cache_cert_status(cert_id, verify_result)
        return True
    
    