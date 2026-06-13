import hashlib
import requests
import time

from cryptography import x509
from utils.data_manager import DataManager
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from config.settings import (
    BACKEND_API_KEY,
    BACKEND_BASE_URL,
    CA_CERT_PATH,
    CA_PRIVATE_KEY_PATH,
    RSU_ID,
    TIMESTAMP_WINDOW_MS,
    EMAIL_HOST,
    EMAIL_PORT,
    EMAIL_USE_TLS,
    EMAIL_USERNAME,
    EMAIL_PASSWORD,
    EMAIL_TO_ADDRESS
)
from log.redisLogger import RedisLogger
import smtplib
from email.message import EmailMessage

from utils.framing import send_framed_packet
class CertificateManager:
    def __init__(self, redis_logger: RedisLogger, data_manager: DataManager) -> None:
        self.redis_logger = redis_logger
        self.data_manager = data_manager

        with open(CA_CERT_PATH, "rb") as f:
            self.ca_cert = x509.load_pem_x509_certificate(f.read())

        with open(CA_PRIVATE_KEY_PATH, "rb") as f:
            self.ca_private_key = serialization.load_pem_private_key(f.read(), password=None)
        
        self.ca_public_key = self.ca_cert.public_key()

    def load_pem_certificate(self, pem_data: bytes):
        return x509.load_pem_x509_certificate(pem_data)
    
    def extract_public_key(self, cert: x509.Certificate):
        return cert.public_key()
    
    def extract_certificate_id(self, cert) -> str:
        return cert.serial_number

    def boradcast_emergency_vehicle_warning(self, cert_id: str):
        message = f"Warning: An emergency vehicle with certificate ID {cert_id} is approaching. Please yield and be cautious.".encode()
        print(f"[+] Broadcasting emergency vehicle warning for certificate ID {cert_id}")
        sessions = self.redis_logger.get_all_sessions()
        for session_id in sessions:
            socket = self.redis_logger.get_logged_socket(session_id)
            if socket:
                try:
                    pkt = self.data_manager.build_data_packet(int(session_id), message)
                    send_framed_packet(socket, pkt)
                    print(f"[+] Sent emergency warning to session {session_id}")
                except Exception as e:
                    pass
    
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
        m.update(timestamp.to_bytes(8,'big'))
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
                ec.ECDSA(Prehashed(hashes.SHA256()))
            )
            return True
        except Exception as e:
            return False
        
    def _headers(self):
        return {
            "X-API-Key": BACKEND_API_KEY
        }

    def send_email_notification(self) -> None:
        msg = EmailMessage()
        msg["Subject"] = "Test Email from Python"
        msg["From"] = EMAIL_USERNAME
        msg["To"] = EMAIL_TO_ADDRESS
        msg.set_content('''
        This is a test email sent from the Python script.''')
        try:
            with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT, timeout=20) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
                server.send_message(msg)
            print("Email sent successfully!")
        except Exception as e:
            print(f"Failed to send email: {e}")
    
    def verify_certificate_with_backend(self, cert_id: str) -> str:
        url = f"{BACKEND_BASE_URL}/api/v1/rsu/verify-certificate/{cert_id}"
        response = requests.get(url, headers=self._headers(), timeout=5)
        if "detail" in response.json():
            return "invalid"
        
        return response.json().get("status")
    
    def check_certificate_revocation(self, cert_id: str) -> bool:
        return False

    def report_certificate_status(self, cert_id: str, status: str) -> None:
        url = f"{BACKEND_BASE_URL}/api/v1/rsu/vehicle/{cert_id}/report"
        data = {
            "certificate_id": cert_id,
            "note": "I have detected a certificate with status: " + status
        }
        try:
            requests.post(url, json=data, headers=self._headers(), timeout=5)
        except Exception as e:
            pass
    
    def check_cetificate_status(self, cert) -> bool:
        cert_id = self.extract_certificate_id(cert)

        cached = self.redis_logger.get_cached_cert_status(cert_id)
        if cached is not None:
            return cached == "regular"
        verify_result = self.verify_certificate_with_backend(cert_id)
        print(f"Certificate ID {cert_id} verification result: {verify_result}")
        if verify_result == "stolen":
            self.report_certificate_status(cert_id, "revoked")
            self.send_email_notification()
            return False
        if not verify_result == "regular" or verify_result == "emergency":
            return False

        rev_result = self.check_certificate_revocation(cert_id)
        if rev_result:
            return False
        
        self.redis_logger.cache_cert_status(cert_id, verify_result)
        return True
    
    