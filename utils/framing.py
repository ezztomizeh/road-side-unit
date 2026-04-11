import struct

def recv_exact(sock, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunck = sock.recv(n - len(data))
        if not chunck:
            raise ConnectionError("Connection closed while receiving data")
        data += chunck
    return data

def recv_framed_packet(sock) -> bytes:
    length_data = recv_exact(sock, 4)
    packet_length = struct.unpack('!I', length_data)[0]
    packet_data = recv_exact(sock, packet_length)
    return packet_data

def send_framed_packet(sock, packet_bytes: bytes)-> None:
    sock.sendall(struct.pack('!I', len(packet_bytes)) + packet_bytes)