import argparse
import socket
import threading
import json
import hashlib
from typing import Dict, Optional
import secrets
import hmac
from argon2.low_level import hash_secret, Type
from hkdf import hkdf_expand, hkdf_extract
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# SRP-6a parameters (same as server)
n = int("""
    EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C
    60756745D262E1B0E824D418D00000000000000000000000000000000
    EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C
    """.replace('\n', '').replace(' ', ''), 16)
g = 2
k = int(hashlib.sha256(f"{n}{g}".encode()).hexdigest(), 16)


class Client:
    def __init__(self, username: str, server_host: str, server_port: int):
        self.username = username
        self.host = server_host
        self.port = server_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.peer.bind(('0.0.0.0', 0))
        self.privkey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.pubkey = self.privkey.public_key()
        self.pubkey_pem = self.pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()        
        self.session_token = None
        self.session_key = None
        self.lock = threading.Lock()
        self.A = None
        self.server_B = None
    
    def run(self):
        threading.Thread(target=self.listen, daemon=True).start()
        try:
            while True:
                try:
                    inp = input("+> ").strip()
                    if not inp:
                        continue
                    parts = inp.split(maxsplit=2)
                    command = parts[0].lower()
                    if command == 'list':
                        self.list()
                    elif command == 'send':
                        self.message(parts[1], parts[2])
                    else:
                        print(f"Unknown command: '{command}'")
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"Error: {e}")
        except KeyboardInterrupt:
            self.sock.close()

    def listen(self):
        while True:
            try:
                data, addr = self.peer.recvfrom(65535)
                try:
                    packet = json.loads(data.decode('utf-8'))
                    if packet.get('type') == 'MESSAGE':
                        sender = packet.get('from')
                        message = packet.get('message')
                        print(f"\n<– <From {addr[0]}:{addr[1]}:{sender}>: {message}")
                        print("+> ", end='', flush=True)
                except json.JSONDecodeError:
                    print(f"Invalid message from {addr}")
            except:
                break
    
    def register(self, password):
        salt = secrets.token_hex(16)        
        hash = hash_secret(
            password.encode(),
            bytes.fromhex(salt),
            time_cost=2,
            memory_cost=65536,
            parallelism=1,
            hash_len=32,
            type=Type.ID
        )
        prk = hkdf_extract(bytes.fromhex(salt), hash, hashlib.sha256)
        x = int.from_bytes(hkdf_expand(prk, b'', 32, hashlib.sha256), byteorder='big')        
        verifier = pow(g, x, n)        
        packet = {
            'type': 'REGISTER',
            'username': self.username,
            'verifier': str(verifier),
            'salt': salt
        }
        response = self.send(packet)
        if response and response.get('success'):
            print(f"You have successfully registered as '{self.username}'")
            return True
        else:
            return False
    
    def login(self, password):
        step1_response = self.signin(password)
        if not step1_response:
            print("Login failed: No response from server")
            return False        
        step2_response = self.send_hmac(password, step1_response)
        if not step2_response:
            print("Login failed: HMAC error")
            return False
        if step2_response.get('success'):
            server_proof = step2_response.get('proof')
            if not self.verify(server_proof, self.session_key):
                print("Login failed: verification failed")
                return False            
            self.session_token = step2_response.get('token')
            print("Authentication successful!")
            return True
        else:
            print(f"Login failed: {step2_response.get('message', 'Unknown error')}")
            return False
    
    def send(self, packet: Dict):
        try:
            self.sock.sendto(json.dumps(packet).encode(), (self.host, self.port))
            self.sock.settimeout(5)
            data, addr = self.sock.recvfrom(65535)
            self.sock.settimeout(None)
            return json.loads(data.decode('utf-8'))
        except socket.timeout:
            print("Error: Server did not respond (timeout)")
            return None
        except Exception as e:
            print(f"Error communicating with server: {e}")
            return None
    
    def signin(self, password):
        self.a = secrets.randbelow(n)
        self.A = pow(g, self.a, n)         
        packet = {
            'type': 'SIGN-IN',
            'username': self.username,
            'A': str(self.A),
            'step': 1
        }
        response = self.send(packet)
        if response and response.get('step') == 2:
            return response
        return None
    
    def send_hmac(self, password: str, response: Dict):
        salt = response.get('salt')
        self.B_server = int(response.get('B'))
        hash = hash_secret(
            password.encode(),
            bytes.fromhex(salt),
            time_cost=2,
            memory_cost=65536,
            parallelism=1,
            hash_len=32,
            type=Type.ID
        )
        prk = hkdf_extract(bytes.fromhex(salt), hash, hashlib.sha256)
        x = int.from_bytes(hkdf_expand(prk, b'', 32, hashlib.sha256), byteorder='big')        
        u = int(hashlib.sha256(f"{self.A}{self.B_server}".encode()).hexdigest(), 16)
        kgx = (k * pow(g, x, n)) % n
        kgx = (self.B_server - kgx) % n
        secret = pow(kgx, self.a + u * x, n) % n        
        prk = hkdf_extract(bytes.fromhex(salt), secret.to_bytes(256, 'big'), hashlib.sha256)
        K = hkdf_expand(prk, b'', 32, hashlib.sha256)        
        self.session_key = K        
        proof = hmac.new(K, (str(self.A) + str(self.B_server)).encode(), hashlib.sha256).hexdigest()        
        packet = {'type': 'SIGN-IN', 'username': self.username,'proof': proof, 'pubkey': self.pubkey_pem,'step': 2}
        response = self.send(packet)
        return response
    
    def verify(self, proof, key) -> bool:
        expected = hmac.new(key, (str(self.B_server) + str(self.A)).encode(), 
                            hashlib.sha256).hexdigest()
        if proof == expected:
            return True
        else:
            return False
    
    def verify_session(self, token):
        pass
    
    def list(self):
        pass
    
    def query(self, username):
        pass
    
    def p2p(self, username):
        pass
    
    def message(self, username, message):
        pass
    
    def signout(self):
        pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--username', type=str, required=True, help='Username')
    parser.add_argument('-r', '--register', action='store_true', help='Register new account')
    parser.add_argument('--host', type=str, required=True, help='Server host')
    parser.add_argument('--port', type=int, required=True, help='Server port')
    args = parser.parse_args()
    client = Client(args.username, args.host, args.port)
    if args.register:
        password = input("Enter password for registration: ")
        client.register(password)
    else:
        password = input("Enter password: ")
        if client.login(password):
            client.run()