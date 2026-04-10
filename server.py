import argparse
import socket
import threading
import json
import hashlib
from typing import Dict, Tuple, Optional
import secrets
import hmac
import time
import os
from hkdf import hkdf_expand, hkdf_extract
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

n = int("""
    EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C
    60756745D262E1B0E824D418D00000000000000000000000000000000
    EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C
    """.replace('\n', '').replace(' ', ''), 16)
g = 2
k = int(hashlib.sha256(f"{n}{g}".encode()).hexdigest(), 16)

class Server:
    def __init__(self, host, port):
        """Initialize server with host and port"""
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, self.port))
        self.users_file = 'users.json'
        self.users = {}
        self.load_users()
        self.clients = {}
        self.sessions: Dict[str, str] = {}
        self.privkey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.pubkey = self.privkey.public_key()
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
                    elif type == 'SIGN-IN':
                        self.authenticate(packet, addr)
                    elif type == 'LIST':
                        self.list(packet, addr)
                    elif type == 'QUERY':
                        self.query(packet, addr)
                    elif type == 'SIGNOUT':
                        self.signout(packet, packet.get('username'), addr)
                except Exception as e:
                    print(f"Error from {addr}: {e}")
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        with self.lock:
            self.clients.clear()
            self.sessions.clear()
            self.save_users()
        self.sock.close()

    def load_users(self):
        """Load users from file if it exists"""
        if os.path.exists(self.users_file):
            try:
                with open(self.users_file, 'r') as f:
                    self.users = json.load(f)
                print(f"Loaded {len(self.users)} users from {self.users_file}")
            except Exception as e:
                print(f"Error loading users from file: {e}")
                self.users = {}
        else:
            self.users = {}

    def save_users(self):
        """Save users to file (must be called with lock held)"""
        try:
            with open(self.users_file, 'w') as f:
                json.dump(self.users, f, indent=2)
            print(f"Saved {len(self.users)} users to {self.users_file}")
        except Exception as e:
            print(f"Error saving users to file: {e}")

    def register(self, message, addr):
        username = message.get('username')
        verifier = int(message.get('verifier'))
        salt = message.get('salt')
        print(f"[REGISTER] Received register request from {addr} for user: {username}")
        with self.lock:
            if username in self.users:
                response = {'type': 'REGISTER-RESP', 'success': False, 'message': 'Username already exists'}
                print(f"[REGISTER] User {username} already exists")
            else:
                self.users[username] = {'verifier': verifier, 'salt': salt}
                print(f"[REGISTER] Saving user {username} to file...")
                self.save_users()
                response = {'type': 'REGISTER-RESP', 'success': True, 'message': 'Registration successful'}
                print(f"[REGISTER] User {username} registered successfully")
        print(f"[REGISTER] Sending response to {addr}: {response}")
        self.sock.sendto(json.dumps(response).encode(), addr)
        print(f"[REGISTER] Response sent")

    def authenticate(self, packet, addr):
        username = packet.get('username')
        step = packet.get('step', 1)
        with self.lock:
            if username not in self.users:
                response = {'type': 'SIGN-IN-RESP', 'success': False, 'message': 'User not found'}
                self.sock.sendto(json.dumps(response).encode(), addr)
                return
            user = self.users[username]
            verifier = user['verifier']
            salt = user['salt']
            if step == 1:
                client_public_A = int(packet.get('A'))
                b = secrets.randbelow(n)
                server_public_B = (k * verifier + pow(g, b, n)) % n
                self.clients[username] = {
                    'b': b,
                    'A': client_public_A,
                    'B': server_public_B,
                    'verifier': verifier,
                    'addr': addr
                }
                response = {
                    'type': 'SIGN-IN-RESP',
                    'step': 2,
                    'salt': salt,
                    'B': str(server_public_B)
                }
                self.sock.sendto(json.dumps(response).encode(), addr)
            elif step == 2:
                proof = packet.get('proof')
                if username not in self.clients:
                    response = {'type': 'SIGN-IN-RESP', 'success': False, 'message': 'Authentication session expired'}
                    self.sock.sendto(json.dumps(response).encode(), addr)
                    return
                session = self.clients[username]
                A = session['A']
                B = session['B']
                u = int(hashlib.sha256(f"{A}{B}".encode()).hexdigest(), 16)
                server_secret = pow(A * pow(verifier, u, n), session['b'], n) % n
                salt_bytes = bytes.fromhex(salt)
                prk = hkdf_extract(salt_bytes, server_secret.to_bytes(256, 'big'), hashlib.sha256)
                K = hkdf_expand(prk, b'', 32, hashlib.sha256)
                expected = hmac.new(K, (str(A) + str(B)).encode(), hashlib.sha256).hexdigest()
                if proof == expected:
                    client_pubkey = packet.get('pubkey')
                    peer_port = packet.get('peer_port', addr[1])
                    self.clients[username] = {'ip': addr[0], 'port': peer_port}
                    print(f"Client {username} registered: {addr[0]}:{peer_port}")
                    proof = hmac.new(K, (str(B) + str(A)).encode(), hashlib.sha256).hexdigest()
                    token = self.create_token(username, client_pubkey)
                    self.sessions[username] = token
                    response = {
                        'type': 'SIGN-IN-RESP',
                        'success': True,
                        'proof': proof,
                        'token': token,
                        'message': 'Authentication successful'
                    }
                else:
                    response = {'type': 'SIGN-IN-RESP', 'success': False, 'message': 'Authentication failed'}
                self.sock.sendto(json.dumps(response).encode(), addr)

    def create_token(self, username, client_pubkey):
        """Create a fresh token with current timestamp"""
        timestamp = int(time.time())
        payload = json.dumps({
            'username': username,
            'pubkey': client_pubkey,
            'timestamp': timestamp
        }).encode()
        signature = self.privkey.sign(payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return {'payload': payload.decode(), 'signature': signature.hex()}

    def verify_token_not_expired(self, token):
        """Verify token signature and check if not expired. Returns (is_valid, payload_dict)"""
        try:
            payload = token['payload'].encode()
            sig = bytes.fromhex(token['signature'])
            self.pubkey.verify(
                sig,
                payload,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            data = json.loads(payload)
            if int(time.time()) - data['timestamp'] > 3600:
                return False, None
            return True, data
        except Exception:
            return False, None

    def list(self, packet, addr):
        token = packet.get('token')
        is_valid, token_data = self.verify_token_not_expired(token)
        if not is_valid:
            self.sock.sendto(json.dumps({'type': 'LIST-RESP', 'success': False, 'message': 'invalid or expired token'}).encode(), addr)
            return
        username = token_data.get('username')
        with self.lock:
            client_pubkey = token_data.get('pubkey')
            new_token = self.create_token(username, client_pubkey)
            self.sessions[username] = new_token
            response = {
                'type': 'LIST-RESP',
                'success': True,
                'list': list(self.clients.keys()),
                'token': new_token
            }
            self.sock.sendto(json.dumps(response).encode(), addr)

    def signout(self, packet, username, addr):
        token = packet.get('token')
        is_valid, token_data = self.verify_token_not_expired(token)
        if not is_valid:
            self.sock.sendto(json.dumps({'type': 'SIGNOUT-RESP', 'success': False, 'message': 'invalid or expired token'}).encode(), addr)
            return
        with self.lock:
            if username in self.clients:
                del self.clients[username]
            if username in self.sessions:
                del self.sessions[username]
            response = {
                'type': 'SIGNOUT-RESP',
                'success': True,
            }
            self.sock.sendto(json.dumps(response).encode(), addr)

    def query(self, packet, addr):
        token = packet.get('token')
        target = packet.get('target')
        is_valid, token_data = self.verify_token_not_expired(token)
        if not is_valid:
            self.sock.sendto(json.dumps({'type': 'QUERY-RESP', 'success': False, 'message': 'invalid or expired token'}).encode(), addr)
            return
        username = token_data.get('username')
        with self.lock:
            if target not in self.clients:
                self.sock.sendto(json.dumps({'type': 'QUERY-RESP', 'success': False, 'message': 'user not online'}).encode(), addr)
                return
            peer = self.clients[target]
            peer_token = self.sessions.get(target)
            client_pubkey = token_data.get('pubkey')
            new_token = self.create_token(username, client_pubkey)
            self.sessions[username] = new_token
        response = {
            'type': 'QUERY-RESP',
            'success': True,
            'ip': peer['ip'],
            'port': peer['port'],
            'token': peer_token,
            'new_token': new_token
        }
        self.sock.sendto(json.dumps(response).encode(), addr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument('--host', type=str, default='localhost', help='Host Address')
    parser.add_argument('--port', type=int, required=True, help='Port')
    args = parser.parse_args()
    server = Server(args.host, args.port)

    pubkey_pem = server.pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open('server_pubkey.pem', 'wb') as f:
        f.write(pubkey_pem)
    print("Server pubkey written to server_pubkey.pem")

    try:
        server.run()
    except KeyboardInterrupt:
        server.stop()
    except Exception as e:
        server.stop()
