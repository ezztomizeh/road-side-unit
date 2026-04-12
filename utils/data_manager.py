from security.encryption_module import CryptoSession
from config.settings import MSG_DATA, PROTOCOL_VERSION
from data.packets import V2VHeader, DataPacket
from logging.redisLogger import RedisLogger

class DataManager:
    def __init__(self, logger: RedisLogger):
        self.logger = logger

    def build_aad(self, header: V2VHeader, sequence_number: int) -> bytes:
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
        
        data_pkt = pkt[DataPacket]
        session_id = pkt.session_id
        seq = data_pkt.sequence_number

        session = self.logger.get_session(session_id)
        if not session:
            raise ValueError(f"Session not found")
        
        session_key = bytes.fromhex(session['key'])
        last_seq = session['last_seq']

        if seq <= last_seq:
            raise ValueError(f"Replay attack detected")
        
        aad = self.build_aad(pkt, seq)

        crypto = CryptoSession(session_key, data_pkt.iv)
        plaintext = crypto.decrypt(data_pkt.ciphertext, data_pkt.tag, aad)

        self.logger.update_session_sequence(session_id, seq)
        return plaintext