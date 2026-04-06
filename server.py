"""
Secure Messaging Protocol - Server
Handles discovery, authentication, and peer connection facilitation
"""

import argparse
import socket
import threading
import json
import hashlib
from typing import Dict, Tuple, Optional
import argon2


class Server:
    def __init__(self, host, port):
        """Initialize server with host and port"""
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, self.port))
        self.clients: Dict[str, Tuple[str, int]] = {}
        self.lock = threading.Lock()
    
    def run(self):
        try:
            while True:
                data, addr = self.sock.recvfrom(65535)
                try:
                    packet = json.loads(data.decode('utf-8'))
                    type = packet.get('type')
                    if type == 'REGISTER':
                        self.register(packet, addr)
                    if type == 'SIGN-IN':
                        self.authenticate(packet, addr)
                    elif type == 'LIST':
                        self.list(addr)
                    elif type == 'QUERY':
                        self.query(packet, addr)
                except Exception as e:
                    print(f"Error from {addr}: {e}")
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self):
        with self.lock:
            self.clients.clear()
        self.sock.close()
        
    def authenticate(self, username: str, password: str):
        """Authenticate client using PAKE (Password-Authenticated Key Exchange)"""
        pass
    
    def register(self, username: str, password: str):
        """Register new client with username and password"""
        pass
    
    def verifier(self, password: str):
        """
        Generate Argon2id password verifier and salt
        """
        pass
        
    def register_client(self, username: str, ip: str, port: int) -> bool:
        """Register client's IP:Port endpoint after authentication"""
        pass
    
    def get_client(self, username: str):
        """Retrieve client information by username"""
        pass
    
    def list(self):
        """Get list of all online clients"""
        pass
    
    def signout(self, username: str):
        """Remove client from registry (client went offline)"""
        pass
        
    def query(self, requester: str, target_username: str):
        """
        Discover peer information for connection establishment
        """
        pass
        
    def parse_request(self, data: str) -> Dict:
        """Parse incoming JSON request"""
        pass
    
    def send_response(self, client_socket: socket.socket, response: Dict):
        """Send JSON response to client"""
        pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-h', type=int, required=True, help='Host Address')
    parser.add_argument('-sp', type=int, required=True, help='Port')
    args = parser.parse_args()
    server = Server(args.sp)
    try:
        server.run()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.stop()
    except Exception as e:
        print(f"Server error: {e}")
        server.stop()

