import time
from log.redisLogger import RedisLogger
from config.settings import TTC_THRESHOLD_SECONDS
from utils.data_manager import DataManager
from utils.framing import send_framed_packet


class IntersectionMonitor:
    def __init__(self, logger: RedisLogger, data_manager: DataManager):
        self.logger = logger
        self.data_manager = data_manager
        self.threshold_seconds = TTC_THRESHOLD_SECONDS

    def add_street_data(self, session_id: str, street_name: str):
        self.logger.store_street_data(session_id, street_name)

    def warn_vehicles_on_street(self, street_name: str):
        message = b"Warning: Possible collision risk ahead on this street. Please slow down and be cautious."
        print(f"[+] Triggering collision warning for street {street_name}")
        self.warn_vehicles(street_name=street_name, warning_type="forward", message=message)

    def warn_vehicles(self, warning_type: str, message: bytes, street_name: str = None):
        if warning_type == "forward":
            sessions = self.logger.get_street_sessions(street_name)
            for session_id in sessions:
                print(session_id)
                pkt = self.data_manager.build_data_packet(int(session_id), message)
                socket = self.logger.get_logged_socket(int(session_id))
                try:
                    send_framed_packet(socket, pkt)
                except Exception as e:
                    print(f"[-] Failed to send collision warning to session {session_id}: {e}")
        elif warning_type == "intersection":
            sessions = self.logger.get_vehicle_intersection_sessions()
            for session_id in sessions:
                pkt = self.data_manager.build_data_packet(int(session_id), message)
                socket = self.logger.get_logged_socket(int(session_id))
                try:
                    send_framed_packet(socket, pkt)
                except Exception as e:
                    print(f"[-] Failed to send collision warning to session {session_id}: {e}")



    def update_vehicle(self, obu_id: int, data: dict):
        start = time.perf_counter()
        if data.get("type") != "intersection":
            return

        try:
            distance = float(data["d"])
            speed = float(data["speed"])
            direction = str(data["direction"]).upper()
        except KeyError as e:
            print(f"[-] Missing field in intersection data: {e}")
            return
        except ValueError:
            print("[-] Invalid distance or speed value")
            return

        vehicle_data = {
            "obu_id": obu_id,
            "type": "intersection",
            "distance": distance,
            "speed": speed,
            "direction": direction,
            "timestamp": time.time(),
            "raw": data
        }

        self.logger.store_vehicle_intersection_data(
            obu_id=obu_id,
            data=vehicle_data
        )


        vehicles = self.logger.get_all_intersection_vehicles()

        if len(vehicles) < 2:
            return

        self.check_collision_risk(vehicles)
        end = time.perf_counter()
        execution_time = (end - start)*1000
        print(f"[+] Collision risk check completed in {execution_time:,.4f} ms")

    def check_collision_risk(self, vehicles):
        for i in range(len(vehicles)):
            for j in range(i + 1, len(vehicles)):
                v1 = vehicles[i]
                v2 = vehicles[j]

                if v1["obu_id"] == v2["obu_id"]:
                    continue

                if not self.are_conflicting_directions(
                    v1["direction"],
                    v2["direction"]
                ):
                    continue

                ttc1 = self.calculate_time_to_intersection(
                    v1["distance"],
                    v1["speed"]
                )

                ttc2 = self.calculate_time_to_intersection(
                    v2["distance"],
                    v2["speed"]
                )

                if ttc1 is None or ttc2 is None:
                    continue

                ttc_difference = abs(ttc1 - ttc2)

                if ttc_difference <= self.threshold_seconds:
                    message = b"Warning: Possible collision risk at the intersection ahead. Please slow down and be cautious."
                    self.warn_vehicles(warning_type="intersection", message=message)

    def calculate_time_to_intersection(self, distance, speed):
        if speed <= 0:
            return None

        return distance / speed

    def are_conflicting_directions(self, dir1, dir2):
        dir1 = dir1.upper()
        dir2 = dir2.upper()

        valid_directions = {"N", "S", "E", "W"}

        if dir1 not in valid_directions or dir2 not in valid_directions:
            return False

        if dir1 == dir2:
            return False

        opposite_pairs = {
            ("N", "S"),
            ("S", "N"),
            ("E", "W"),
            ("W", "E"),
        }

        if (dir1, dir2) in opposite_pairs:
            return False

        return True

    def print_collision_warning(self, v1, v2, ttc1, ttc2, ttc_difference):
        print("\n" + "=" * 60)
        print("[!] POSSIBLE COLLISION RISK")
        print(f"    OBU 1: {v1['obu_id']}")
        print(f"    Direction: {v1['direction']}")
        print(f"    Distance: {v1['distance']} m")
        print(f"    Speed: {v1['speed']} m/s")
        print(f"    TTC: {ttc1:.2f} s")
        print()
        print(f"    OBU 2: {v2['obu_id']}")
        print(f"    Direction: {v2['direction']}")
        print(f"    Distance: {v2['distance']} m")
        print(f"    Speed: {v2['speed']} m/s")
        print(f"    TTC: {ttc2:.2f} s")
        print()
        print(f"    TTC difference: {ttc_difference:.2f} s")
        print(f"    Threshold: {self.threshold_seconds:.2f} s")
        print("=" * 60 + "\n")