import hashlib
import hmac
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from config.settings import (
    MSG_CLINET_HELLO,
    MSG_SERVER_HELLO,
    MSG_SESSION_CONFIRM,
    PROTOCOL_VERSION,
    MSG_SESSION_ESTABLISHED
)
from data.packets import V2VHeader, ClientHello, ServerHello, SessionConfirm, SessionEstablished
from utils.cert_utils import CertificateManager
from log.redisLogger import RedisLogger

class HandshakeManager:
    def __init__(self, cert_manager: CertificateManager, logger: RedisLogger):
        self.cert_manager = cert_manager
        self.logger = logger

    def parse_client_hello(self, raw_bytes: bytes):
        pkt = V2VHeader(raw_bytes)
        if pkt.msg_type != PROTOCOL_VERSION:
            raise ValueError("Unsupported protocol version")
        client_hello = pkt.payload

        if not isinstance(client_hello, ClientHello):
            client_hello = ClientHello(bytes(client_hello))

        if pkt.msg_type != MSG_CLINET_HELLO:
            raise ValueError("Not CLIENT_HELLO")
        
        return pkt,client_hello
    
    def validate_client_hello(self, raw_bytes: bytes) -> dict:
        _, ch = self.parse_client_hello(raw_bytes)
        cert = self.cert_manager.load_pem_certificate(ch.certificate)

        if not self.cert_manager.verify_certificate_signature(cert):
            raise ValueError("Invalid certificate signature")
                 
        if not self.cert_manager.verify_timestamp(ch.timestamp):
            raise ValueError("Certificate expired or not yet valid")
        
        if not self.cert_manager.check_cetificate_status(cert):
            raise ValueError("Certificate revoked")
        
                
        public_key = self.cert_manager.extract_public_key(cert)
        msg_hash = self.cert_manager.client_hello_hash(ch.client_nonce, ch.timestamp)

        if not self.cert_manager.verify_raw_ecdsa_signature(public_key, msg_hash, ch.signature):
            raise ValueError("Invalid client proof-of-possession signature")
        
        return {
            "cert": cert,
            "certificate_id": self.cert_manager.extract_certificate_id(cert),
            "obu_public_key": public_key,
            "client_nonce": ch.client_nonce
        }
    
    def _generate_ephemeral_pub_bytes(self, public_key) -> bytes:
        numbers = public_key.public_numbers()
        return b"\x04" + numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big")
    
    def _derive_wrapping_key(self, shared_secret: bytes,
                              client_nonce: bytes, server_nonce: bytes) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=client_nonce + server_nonce,
            info=b"V2V session key",
        )
        return hkdf.derive(shared_secret)
    
    def _sign_server_hello(self, client_nonce: bytes, server_nonce: bytes,
                           eph_pub_bytes: bytes) -> bytes:
        digest = hashlib.sha256(client_nonce + 
                                server_nonce + 
                                eph_pub_bytes).digest()
        der_sig = self.cert_manager.ca_private_key.sign(
            digest,
            ec.ECDSA(hashes.SHA256())
        )
        r, s = decode_dss_signature(der_sig)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
    
    def generate_server_hello(self, validated: dict) -> tuple[bytes, int]:
        client_nonce = validated["client_nonce"]
        obu_public_key = validated["obu_public_key"]

        handshake_id = int.from_bytes(os.urandom(8), "big")
        server_nonce = os.urandom(16)

        eph_priv = ec.generate_private_key(ec.SECP256R1())
        eph_pub = eph_priv.public_key()
        eph_pub_bytes = self._generate_ephemeral_pub_bytes(eph_pub)

        shared_secret = eph_priv.exchange(ec.ECDH(), obu_public_key)
        print(f"[DEBUG] client nonce: {client_nonce.hex()}")
        print(f"[DEBUG] server nonce: {server_nonce.hex()}")
        wrapping_key = self._derive_wrapping_key(shared_secret, client_nonce, server_nonce)
        print(f"[+] Wrapping key derived: {wrapping_key.hex()}")

        session_key = os.urandom(16)
        aesgcm = AESGCM(wrapping_key)
        iv = os.urandom(12)
        encrypted_session_key = iv + aesgcm.encrypt(iv, session_key, None)

        signature = self._sign_server_hello(client_nonce, server_nonce, eph_pub_bytes)

        pkt = V2VHeader(
            version=PROTOCOL_VERSION,
            msg_type=MSG_SERVER_HELLO,
            session_id=0,
            total_length=0
        ) / ServerHello(
            handshake_id=handshake_id,
            server_nonce=server_nonce,
            pubkey_length=len(eph_pub_bytes),
            pubkey=eph_pub_bytes,
            enc_key_length=len(encrypted_session_key),
            enc_key=encrypted_session_key,
            signature_length=len(signature),
            signature=signature
        )

        pkt[V2VHeader].total_length = len(bytes(pkt))
        self.logger.store_pending_handshake(handshake_id=handshake_id, data={
            "client_nonce": client_nonce.hex(),
            "server_nonce": server_nonce.hex(),
            "session_key": session_key.hex(),
        })

        return bytes(pkt), handshake_id
    
    def verify_session_confirm(self, raw_data: bytes) -> int:
        pkt = V2VHeader(raw_data)

        if pkt.version != PROTOCOL_VERSION:
            raise ValueError("Unsupported protocol version")
        
        if pkt.msg_type != MSG_SESSION_CONFIRM:
            raise ValueError("Not SESSION_CONFIRM")
        
        sc = pkt.payload
        print(f"[DEBUG] SessionConfirm payload: {sc}")
        if not isinstance(sc, SessionConfirm):
            sc = SessionConfirm(bytes(sc))
        
        pending = self.logger.get_pending_handshake(sc.handshake_id)
        if not pending:
            raise ValueError("No pending handshake for this ID")
        client_nonce = bytes.fromhex(pending["client_nonce"])
        server_nonce = bytes.fromhex(pending["server_nonce"])
        session_key = bytes.fromhex(pending["session_key"])

        if sc.client_nonce != client_nonce:
            raise ValueError("Client nonce mismatch")
        if sc.server_nonce != server_nonce:
            raise ValueError("Server nonce mismatch")
        
        expected_tag = hmac.new(
            session_key,
            client_nonce + server_nonce,
            hashlib.sha256
        ).digest()

        if not hmac.compare_digest(expected_tag, sc.auth_tag):
            raise ValueError("Invalid session confirmation tag")
        
        session_id = int.from_bytes(os.urandom(8), "big")
        self.logger.store_session(session_id, session_key,
                                  client_nonce, server_nonce)
        self.logger.delete_pending_handshake(sc.handshake_id)
        return session_id
    
    def _sign_session_established(self, session_id: bytes) -> bytes:
        digest = hashlib.sha256(session_id).digest()
        der_sig = self.cert_manager.ca_private_key.sign(
            digest,
            ec.ECDSA(hashes.SHA256())
        )
        r, s = decode_dss_signature(der_sig)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
    

    def build_session_established(self, session_id: int) -> bytes:
        signature = self._sign_session_established(session_id.to_bytes(8, "big"))
        pkt = V2VHeader(
            version=PROTOCOL_VERSION,
            msg_type=MSG_SESSION_ESTABLISHED,
            session_id=session_id,
            total_length=0
        ) / SessionEstablished(
            session_id=session_id,
            signature_length=len(signature),
            signature=signature
        )

        pkt[V2VHeader].total_length = len(bytes(pkt))
        return bytes(pkt)