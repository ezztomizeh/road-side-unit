from security.encryption_module import CryptoSession
from config.settings import MSG_DATA, PROTOCOL_VERSION
from data.packets import V2VHeader, DataPacket
from log.redisLogger import RedisLogger
from scapy.packet import Packet
import os

class DataManager:
    def __init__(self, logger: RedisLogger):
        self.logger = logger

    def build_aad(self, header:Packet, sequence_number: int) -> bytes:
        return (
            bytes([header.version]) +
            bytes([header.msg_type]) +
            header.session_id.to_bytes(8, 'big') + 
            sequence_number.to_bytes(8, 'big') 
        )
    
    def handle_data_packet(self, raw_bytes: bytes) -> bytes:
        pkt = V2VHeader(raw_bytes)

        if pkt.version != PROTOCOL_VERSION:
            raise ValueError(f"Unsupported protocol version")
        if pkt.msg_type != MSG_DATA:
            raise ValueError(f"Not DATA packet")
        
        data_pkt = pkt.payload

        if not isinstance(data_pkt, DataPacket):
            data_pkt = DataPacket(bytes(data_pkt))

        session_id = pkt.session_id
        seq = data_pkt.sequence_number

        session = self.logger.get_session(session_id)
        if not session:
            raise ValueError(f"Session not found")
        
        session_key = bytes.fromhex(session['key'])
        last_seq = session.get("rx_last_seq", -1)

        if seq <= last_seq:
            raise ValueError(f"Replay attack detected")
        
        aad = self.build_aad(pkt, seq)
        crypto = CryptoSession(session_key, data_pkt.iv)
        plaintext = crypto.decrypt(data_pkt.ciphertext, data_pkt.auth_tag, aad)

        self.logger.update_rx_sequence(session_id, seq)
        return plaintext

    def build_data_packet(self, session_id: int, plaintext: bytes) -> bytes:
        session = self.logger.get_session(session_id)
        if not session:
            raise ValueError("Session not found")

        session_key = bytes.fromhex(session["key"])
        sequence_number = self.logger.get_tx_sequence(session_id)

        iv = os.urandom(16)

        header = V2VHeader(
            version=PROTOCOL_VERSION,
            msg_type=MSG_DATA,
            session_id=session_id,
            total_length=0
        )

        aad = self.build_aad(header, sequence_number)

        crypto = CryptoSession(session_key, iv)
        ciphertext, auth_tag = crypto.encrypt(plaintext, aad)

        pkt = header / DataPacket(
            sequence_number=sequence_number,
            iv=iv,
            data_length=len(ciphertext),
            ciphertext=ciphertext,
            auth_tag=auth_tag
        )

        pkt[V2VHeader].total_length = len(bytes(pkt))

        self.logger.increment_tx_sequence(session_id)

        return bytes(pkt)

