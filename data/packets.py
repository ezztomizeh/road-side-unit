from scapy.all import Packet
from scapy.fields import (
    ByteField,
    ByteEnumField,
    ShortField,
    IntField,
    LongField,
    StrFixedLenField,
    StrLenField
)

class V2VHeader(Packet):
    name = "V2VHeader"
    fields_desc = [
        ByteField("version", 1),
        ByteEnumField("msg_type",0,
                      {1: "CLIENT_HELLO",
                       2: "SERVER_HELLO",
                       3: "SESSION_CONFIRM",
                       4: "DATA",
                       5: "SESSION_ESTABLISHED"}),
        LongField("session_id", 0),
        IntField("total_length", 0),
    ]

class ClientHello(Packet):
    name = "ClientHello"
    fields_desc = [
        StrFixedLenField("client_nonce", b"\x00"*16, length=16),
        LongField("timestamp", 0),
        IntField("cert_length", 0),
        StrLenField("certificate", b"", length_from=lambda pkt: pkt.cert_length),
        ShortField("signature_length", 0),
        StrLenField("signature", b"", length_from=lambda pkt: pkt.signature_length),
        ]
    
class ServerHello(Packet):
    name = "ServerHello"
    fields_desc = [
        LongField("handshake_id", 0),
        StrFixedLenField("server_nonce", b"\x00"*16, length=16),
        ShortField("pubkey_length", 0),
        StrLenField("pubkey", b"", length_from=lambda pkt: pkt.pubkey_length),
        ShortField("enc_key_length", 0),
        StrLenField("enc_key", b"", length_from=lambda pkt: pkt.enc_key_length),
        ShortField("signature_length", 0),
        StrLenField("signature", b"", length_from=lambda pkt: pkt.signature_length),
        ]
    
class SessionConfirm(Packet):
    name = "SessionConfirm"
    fields_desc = [
        LongField("handshake_id", 0),
        StrFixedLenField("client_nonce", b"\x00"*16, length=16),
        StrFixedLenField("server_nonce", b"\x00"*16, length=16),
        StrFixedLenField("auth_tag", b"\x00"*32, length=32),
        ]
    
class DataPacket(Packet):
    name = "DataPacket"
    fields_desc = [
        LongField("sequence_number", 0),
        StrFixedLenField("iv", b"\x00"*16, length=16),
        ShortField("data_length", 0),
        StrLenField("ciphertext", b"", length_from=lambda pkt: pkt.data_length),
        StrFixedLenField("auth_tag", b"\x00"*16, length=16),
        ]
    
class SessionEstablished(Packet):
    name = "SessionEstablished"
    fields_desc = [
        LongField("session_id", 0),
        ShortField("signature_length", 0),
        StrLenField("signature", b"", length_from=lambda pkt: pkt.signature_length)
        ]