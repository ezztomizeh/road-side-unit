from config.settings import BACKEND_API_KEY, BACKEND_BASE_URL
from test import send_framed_packet
from utils.data_manager import DataManager

import requests


class VehicleTrackingManager:
    def __init__(self,data_manager: DataManager, session_id: int):
        self.data_manager = data_manager
        self.session_id = session_id

    def _headers(self):
        return {
            "X-API-Key": BACKEND_API_KEY
        }

    def report_stolen_vehicle(self, cert_id: str, longtiude, latitude):
        url = f"{BACKEND_BASE_URL}/api/v1/rsu/verify-certificate/{cert_id}"
        data = {
            "certificate_id": cert_id,
            "longitude": longtiude,
            "latitude": latitude
        }
        try:            
            requests.post(url, json=data, headers=self._headers(), timeout=5)
        except Exception as e:
            print(f"[!] Error occurred while reporting stolen vehicle: {e}")

    def get_vehicle_location(self, socket):
        msg = b"Requesting current location of the vehicle"
        pkt = self.data_manager.build_data_packet(self.session_id, msg)
        try:            
            send_framed_packet(socket, pkt)
            print(f"[+] Sent location request to session {self.session_id}")
        except Exception as e:
            print(f"[!] Error occurred while requesting vehicle location: {e}")