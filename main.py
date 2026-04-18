import socket
import threading

from config.settings import (
    RSU_HOST,
    RSU_PORT,
    MSG_CLINET_HELLO,
    MSG_SESSION_CONFIRM,
    MSG_DATA
)
from data.packets import V2VHeader
from utils.framing import recv_framed_packet, send_framed_packet
from log.redisLogger import RedisLogger
from utils.cert_utils import CertificateManager
from utils.handshake_manager import HandshakeManager
from utils.data_manager import DataManager

class ClientThread(threading.Thread):
    def __init__(self, client_socket: socket.socket, address,
                 handshake_manager: HandshakeManager, data_manager: DataManager):
        super().__init__(daemon=True)
        self.client_socket = client_socket
        self.address = address
        self.handshake_manager = handshake_manager
        self.data_manager = data_manager
        self.authenticated = False
        self.session_id = None

    def run(self):
        print(f"[+] Connection from {self.address}")
        try:
            while True:
                raw_packet = recv_framed_packet(self.client_socket)
                header = V2VHeader(raw_packet)

                if header.msg_type == MSG_CLINET_HELLO:
                    self.handle_client_hello(raw_packet)
                
                elif header.msg_type == MSG_SESSION_CONFIRM:
                    self.handle_session_confirm(raw_packet)
                
                elif header.msg_type == MSG_DATA:
                    self.handle_data(raw_packet)

                else:
                    print(f"[-] Unknown message type from {self.address}: {header.msg_type}")
        except ConnectionError:
            print(f"[-] Client Disconnected: {self.address}")
        
        except Exception as e:
            print(f"[-] Error handling client {self.address}: {e}")
        
        finally:
            self.client_socket.close()

    def handle_client_hello(self, raw_packet: bytes):
        validated = self.handshake_manager.validate_client_hello(raw_packet)
        server_hello_bytes, handshake_id = self.handshake_manager.generate_server_hello(validated)
        send_framed_packet(self.client_socket, server_hello_bytes)
        print(f"[+] Sent Server Hello to {self.address} with Handshake ID: {handshake_id}")

    def handle_session_confirm(self, raw_packet: bytes):
        session_id = self.handshake_manager.verify_session_confirm(raw_packet)
        self.authenticated = True
        self.session_id = session_id
        established_bytes = self.handshake_manager.build_session_established(session_id)
        send_framed_packet(self.client_socket, established_bytes)
        print(f"[+] Secure session established with {self.address}, Session ID: {session_id}")

    def handle_data(self, raw_packet: bytes):
        if not self.authenticated:
            raise ValueError("DATA recieved before authentication")
        
        plaintext = self.data_manager.handle_data_packet(raw_packet)
        print(f"[DATA] FROM {self.address}: {plaintext!r}")

class RSUServer:
    def __init__(self, host=RSU_HOST, port=RSU_PORT):
        self.host = host
        self.port = port

        self.logger = RedisLogger()
        self.cert_manager = CertificateManager(self.logger)
        self.handshake_manager = HandshakeManager(self.cert_manager, self.logger)
        self.data_manager = DataManager(self.logger)

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(10)

        print(f"[RSU] Listening on {self.host}:{self.port}")

        try:
            while True:
                client_socket, address = server_socket.accept()
                worker = ClientThread(client_socket, address, self.handshake_manager, self.data_manager)
                worker.start()
        finally:
            server_socket.close()

if __name__ == "__main__":
    server = RSUServer()
    server.start()
