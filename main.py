import json
import socket
import threading
import time

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
from utils.collision_warning import IntersectionMonitor
from utils.vehicle_tracking_manager import VehicleTrackingManager

class ClientThread(threading.Thread):
    def __init__(self, client_socket: socket.socket, address,
                 handshake_manager: HandshakeManager, data_manager: DataManager,
                   collision_monitor: IntersectionMonitor, logger: RedisLogger,
                   vehicle_tracking_manager: VehicleTrackingManager):
        super().__init__(daemon=True)
        self.client_socket = client_socket
        self.address = address
        self.handshake_manager = handshake_manager
        self.data_manager = data_manager
        self.logger = logger
        self.collision_monitor = collision_monitor
        self.vehicle_tracking_manager = vehicle_tracking_manager
        self.authenticated = False
        self.session_id = None
        self.__tx_sequence_number = 0
        self.__is_stolen = False
        self.__certificate_id = None

    def run(self):
        print(f"[+] Connection from {self.address}")
        try:
            while True:
                start_time = time.perf_counter()
                raw_packet = recv_framed_packet(self.client_socket)
                header = V2VHeader(raw_packet)

                if self.authenticated and self.__is_stolen:
                    self.vehicle_tracking_manager.get_vehicle_location(self.client_socket)

                if header.msg_type == MSG_CLINET_HELLO:
                    self.handle_client_hello(raw_packet)
                
                elif header.msg_type == MSG_SESSION_CONFIRM:
                    end_time = time.perf_counter()
                    execution_time = end_time - start_time
                    print(f"[TESTING] Time to receive and parse Session Confirm: {execution_time*1000:.4f} ms")
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
        self.__certificate_id = validated["certificate_id"]


        if validated["status"] == "stolen":
            print(f"[!] Vehicle with certificate ID {self.__certificate_id} is reported stolen. Marking session as stolen.")
            self.__is_stolen = True
        

        server_hello_bytes, handshake_id = self.handshake_manager.generate_server_hello(validated)
        send_framed_packet(self.client_socket, server_hello_bytes)
        print(f"[+] Sent Server Hello to {self.address} with Handshake ID: {handshake_id}")

    def handle_session_confirm(self, raw_packet: bytes):
        session_id = self.handshake_manager.verify_session_confirm(raw_packet)
        self.authenticated = True
        self.session_id = int(session_id)
        self.logger.log_socket(session_id, self.client_socket)

        established_bytes = self.handshake_manager.build_session_established(session_id)
        send_framed_packet(self.client_socket, established_bytes)
        print(f"[+] Secure session established with {self.address}, Session ID: {session_id}")

    def handle_data(self, raw_packet: bytes):
        if not self.authenticated:
            raise ValueError("DATA received before authentication")

        plaintext = self.data_manager.handle_data_packet(raw_packet)
        print(f"[DATA] FROM {self.address}: {plaintext!r}")

        try:
            data_json = json.loads(plaintext)
            if data_json.get("type") == "intersection":
                print(f"[+] Received intersection data from {self.address}, updating collision monitor")
                _ = self.collision_monitor.update_vehicle(obu_id=self.session_id, data=data_json),
            elif data_json.get("type") == "forward":
                print(f"[+] Received forward data from {self.address}, updating collision monitor")
                self.collision_monitor.add_street_data(session_id=self.session_id, street_name=data_json.get("street_name"))
            elif data_json.get("type") == "warning":
                print(f"[+] Received warning data from {self.address}, updating collision monitor")
                self.collision_monitor.warn_vehicles_on_street(street_name=data_json.get("street_name"))
            elif data_json.get("type") == "location":
                print(f"[+] Received location data from {self.address}, updating vehicle tracking manager")
                self.vehicle_tracking_manager.report_stolen_vehicle(cert_id=self.__certificate_id, longtiude=data_json.get("longitude"), latitude=data_json.get("latitude"))
            else:
                print(f"[-] data : {data_json}")
                print(f"[-] Unknown data type received from {self.address}")
                return
        except json.JSONDecodeError:
            print("[-] Received non-JSON data, skipping collision check")

class RSUServer:
    def __init__(self, host=RSU_HOST, port=RSU_PORT):
        self.host = host
        self.port = port

        self.logger = RedisLogger()
        self.cert_manager = CertificateManager(self.logger, DataManager(self.logger))
        self.handshake_manager = HandshakeManager(self.cert_manager, self.logger)
        self.data_manager = DataManager(self.logger)
        self.collision_monitor = IntersectionMonitor(self.logger, self.data_manager)
        self.vehicle_tracking_manager = VehicleTrackingManager(self.data_manager, session_id=None)

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(10)

        print(f"[RSU] Listening on {self.host}:{self.port}")

        try:
            while True:
                start_time = time.perf_counter()
                client_socket, address = server_socket.accept()
                worker = ClientThread(client_socket, address, 
                                      self.handshake_manager,
                                      self.data_manager,self.collision_monitor,
                                      self.logger, self.vehicle_tracking_manager)
                worker.start()
        finally:
            server_socket.close()

if __name__ == "__main__":
    server = RSUServer()
    server.start()
