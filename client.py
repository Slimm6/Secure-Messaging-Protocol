import os
import time
import argparse
import socket
import threading
import json
import hashlib
from typing import Dict, Optional
import secrets
import hmac
from urllib import response
from argon2.low_level import hash_secret, Type
from hkdf import hkdf_expand, hkdf_extract
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

n = int("""
    EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C
    60756745D262E1B0E824D418D00000000000000000000000000000000
    EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C
    """.replace('\n', '').replace(' ', ''), 16)
g = 2
k = int(hashlib.sha256(f"{n}{g}".encode()).hexdigest(), 16)


class Client:
    def __init__(self, username, host, port, server_pubkey=None):
        self.username = username
        self.host = host
        self.port = port
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
        self.server_pubkey = server_pubkey
        self.lock = threading.Lock()
        self.A = None
        self.server_B = None
        self.peer_sessions = {}
        self.seq_tracker = {}

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
                        response = self.list()
                        if response and response.get('success'):
                            users = response.get('list', [])
                            print("Online users:")
                            for u in users:
                                print(f" - {u}")
                    elif command == 'send':
                        self.message(parts[1], parts[2])
                    elif command == 'signout':
                        self.signout()
                        self.sock.close()
                        break
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
                    ptype = packet.get('type')
                    if ptype == 'MESSAGE':
                        sender = packet.get('from')
                        seq_no = packet.get('seq')
                        with self.lock:
                            key = self.peer_sessions.get(sender)
                            last_seq = self.seq_tracker.get(sender, -1)
                        if key is None or seq_no is None or seq_no <= last_seq:
                            print("+> ", end='', flush=True)
                        else:
                            try:
                                expected_mac = hmac.new(key, bytes.fromhex(packet['nonce']) + bytes.fromhex(packet['ciphertext']), hashlib.sha256).hexdigest()
                                if not hmac.compare_digest(expected_mac, packet['mac']):
                                    print(f"\nMessage from {sender} failed HMAC, dropping")
                                else:
                                    plaintext = AESGCM(key).decrypt(bytes.fromhex(packet['nonce']), bytes.fromhex(packet['ciphertext']), None)
                                    with self.lock:
                                        self.seq_tracker[sender] = seq_no
                                    print(f"\n<– <From {sender}>: {plaintext.decode()}")
                            except Exception as e:
                                print(f"\nFailed to decrypt message from {sender}: {e}")
                            print("+> ", end='', flush=True)
                    elif ptype == 'KEY-INIT':
                        threading.Thread(target=self.handle_key_init, args=(packet, addr), daemon=True).start()
                    else:
                        pass
                except json.JSONDecodeError:
                    print(f"Invalid message from {addr}")
            except Exception as e:
                print(f"\nlisten() exception: {e}", flush=True)
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
        k = hkdf_extract(bytes.fromhex(salt), hash, hashlib.sha256)
        x = int.from_bytes(hkdf_expand(k, b'', 32, hashlib.sha256), byteorder='big')
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
        step1 = self.signin(password)
        if not step1:
            print("Login failed: No response from server")
            return False
        step2 = self.send_hmac(password, step1)
        if not step2:
            print("Login failed: HMAC error")
            return False
        if step2.get('success'):
            proof = step2.get('proof')
            if not self.verify(proof, self.session_key):
                print("Login failed: verification failed")
                return False
            self.session_token = step2.get('token')
            print("Authentication successful!")
            return True
        else:
            print(f"Login failed: {step2.get('message', 'Unknown error')}")
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
        prk2 = hkdf_extract(bytes.fromhex(salt), secret.to_bytes(256, 'big'), hashlib.sha256)
        K = hkdf_expand(prk2, b'', 32, hashlib.sha256)
        self.session_key = K
        proof = hmac.new(K, (str(self.A) + str(self.B_server)).encode(), hashlib.sha256).hexdigest()
        peer_port = self.peer.getsockname()[1]
        packet = {'type': 'SIGN-IN', 'username': self.username, 'proof': proof, 'pubkey': self.pubkey_pem, 'peer_port': peer_port, 'step': 2}
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
        try:
            payload = token['payload'].encode()
            signature = bytes.fromhex(token['signature'])
            self.server_pubkey.verify(
                signature,
                payload,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            data = json.loads(payload)
            if int(time.time()) - data['timestamp'] > 3600:
                return False
            return True
        except Exception as e:
            return False

    def list(self):
        packet = {
            'type': 'LIST',
            'token': self.session_token
        }
        response = self.send(packet)
        if response and response.get('success'):
            if response.get('token'):
                self.session_token = response.get('token')
            return response
        print(f"list fail: {response.get('message') if response else 'no response'}")
        return None

    def query(self, username):
        packet = {
            'type': 'QUERY',
            'token': self.session_token,
            'target': username
        }
        response = self.send(packet)
        if response and response.get('success'):
            if response.get('new_token'):
                self.session_token = response.get('new_token')
            return response
        print(f"query fail: {response.get('message') if response else 'no response'}")
        return None

    def p2p(self, username):
        info = self.query(username)
        if not info:
            return None
        peer_ip = info['ip']
        peer_port = int(info['port'])
        peer_token = info['token']
        if not self.verify_session(peer_token):
            return None
        init_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        init_sock.bind(('0.0.0.0', 0))
        init_port = init_sock.getsockname()[1]
        eph_priv = X25519PrivateKey.generate()
        eph_pub = eph_priv.public_key()
        eph_pub_bytes = eph_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        init_packet = {
            'type': 'KEY-INIT',
            'from': self.username,
            'eph_pub': eph_pub_bytes.hex(),
            'token': self.session_token,
            'init_port': init_port
        }
        self.peer.sendto(json.dumps(init_packet).encode(), (peer_ip, peer_port))
        init_sock.settimeout(5)
        try:
            data, _ = init_sock.recvfrom(65535)
        except socket.timeout:
            init_sock.close()
            return None
        finally:
            init_sock.settimeout(None)
        resp = json.loads(data.decode())
        if resp.get('type') != 'KEY-RESP':
            print("Unexpected response during key establishment")
            init_sock.close()
            return None
        peer_eph_pub_bytes = bytes.fromhex(resp['eph_pub'])
        peer_sig = bytes.fromhex(resp['sig'])
        peer_token_resp = resp['token']
        peer_hs_port = int(resp['hs_port'])
        if not self.verify_session(peer_token_resp):
            print("peer token invalid in KEY-RESP")
            init_sock.close()
            return None
        peer_payload = json.loads(peer_token_resp['payload'])
        peer_lt_pubkey = serialization.load_pem_public_key(peer_payload['pubkey'].encode())
        try:
            peer_lt_pubkey.verify(
                peer_sig,
                eph_pub_bytes + peer_eph_pub_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except InvalidSignature:
            print("peer STS signature invalid")
            init_sock.close()
            return None
        our_sig = self.privkey.sign(
            eph_pub_bytes + peer_eph_pub_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        ack_packet = {'type': 'KEY-ACK', 'from': self.username, 'sig': our_sig.hex()}
        init_sock.sendto(json.dumps(ack_packet).encode(), (peer_ip, peer_hs_port))
        nonce = secrets.token_bytes(16)
        init_sock.sendto(
            json.dumps({'type': 'NONCE', 'nonce': nonce.hex(), 'from': self.username}).encode(),
            (peer_ip, peer_hs_port)
        )
        init_sock.settimeout(5)
        try:
            data, _ = init_sock.recvfrom(65535)
        except socket.timeout:
            init_sock.close()
            return None
        finally:
            init_sock.settimeout(None)
        peer_nonce = bytes.fromhex(json.loads(data.decode())['nonce'])
        init_sock.close()
        peer_eph_pub = X25519PublicKey.from_public_bytes(peer_eph_pub_bytes)
        shared_secret = eph_priv.exchange(peer_eph_pub)
        k = hkdf_extract(nonce + peer_nonce, shared_secret, hashlib.sha256)
        session_key = hkdf_expand(k, b'session', 32, hashlib.sha256)
        return {'key': session_key, 'ip': peer_ip, 'port': peer_port}

    def handle_key_init(self, packet, addr):
        sender = packet.get('from')
        peer_init_port = packet.get('init_port')
        peer_eph_pub_bytes = bytes.fromhex(packet['eph_pub'])
        peer_token = packet['token']
        if not self.verify_session(peer_token):
            return
        hs_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        hs_sock.bind(('0.0.0.0', 0))
        hs_port = hs_sock.getsockname()[1]
        eph_priv = X25519PrivateKey.generate()
        eph_pub = eph_priv.public_key()
        eph_pub_bytes = eph_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        our_sig = self.privkey.sign(
            peer_eph_pub_bytes + eph_pub_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        resp = {
            'type': 'KEY-RESP',
            'from': self.username,
            'eph_pub': eph_pub_bytes.hex(),
            'token': self.session_token,
            'sig': our_sig.hex(),
            'hs_port': hs_port
        }
        reply_addr = (addr[0], peer_init_port)
        hs_sock.sendto(json.dumps(resp).encode(), reply_addr)
        hs_sock.settimeout(5)
        try:
            data, ack_addr = hs_sock.recvfrom(65535)
        except socket.timeout:
            hs_sock.close()
            return
        finally:
            hs_sock.settimeout(None)
        ack = json.loads(data.decode())
        if ack.get('type') != 'KEY-ACK':
            hs_sock.close()
            return
        peer_payload = json.loads(peer_token['payload'])
        peer_lt_pubkey = serialization.load_pem_public_key(peer_payload['pubkey'].encode())
        try:
            peer_lt_pubkey.verify(
                bytes.fromhex(ack['sig']),
                peer_eph_pub_bytes + eph_pub_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except InvalidSignature:
            hs_sock.close()
            return
        hs_sock.settimeout(5)
        try:
            data, _ = hs_sock.recvfrom(65535)
        except socket.timeout:
            hs_sock.close()
            return
        finally:
            hs_sock.settimeout(None)
        nonce_pkt = json.loads(data.decode())
        peer_nonce = bytes.fromhex(nonce_pkt['nonce'])
        our_nonce = secrets.token_bytes(16)
        hs_sock.sendto(
            json.dumps({'type': 'NONCE', 'nonce': our_nonce.hex(), 'from': self.username}).encode(),
            reply_addr
        )
        hs_sock.close()
        peer_eph_pub = X25519PublicKey.from_public_bytes(peer_eph_pub_bytes)
        shared_secret = eph_priv.exchange(peer_eph_pub)
        k = hkdf_extract(peer_nonce + our_nonce, shared_secret, hashlib.sha256)
        session_key = hkdf_expand(k, b'session', 32, hashlib.sha256)
        with self.lock:
            self.peer_sessions[sender] = session_key
        print("+> ", end='', flush=True)

    def message(self, username, message):
        session = self.p2p(username)
        if not session:
            print(f"Could not establish session with {username}")
            return
        key = session['key']
        peer_addr = (session['ip'], session['port'])
        with self.lock:
            self.peer_sessions[username] = key
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(key).encrypt(nonce, message.encode(), None)
        mac = hmac.new(key, nonce + ciphertext, hashlib.sha256).hexdigest()
        seq = int(time.time())
        packet = {
            'type': 'MESSAGE',
            'from': self.username,
            'seq': seq,
            'nonce': nonce.hex(),
            'ciphertext': ciphertext.hex(),
            'mac': mac
        }
        self.peer.sendto(json.dumps(packet).encode(), peer_addr)
        print(f"Message sent to {username}")

    def signout(self):
        packet = {
            'type': 'SIGNOUT',
            'token': self.session_token,
            'username': self.username
        }
        response = self.send(packet)
        if response and response.get('success'):
            return response
        print(f"signout fail: {response.get('message') if response else 'no response'}")
        return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--username', type=str, required=True, help='Username')
    parser.add_argument('-r', '--register', action='store_true', help='Register new account')
    parser.add_argument('--host', type=str, required=True, help='Server host')
    parser.add_argument('--port', type=int, required=True, help='Server port')
    args = parser.parse_args()
    with open('server_pubkey.pem', 'rb') as f:
        server_pubkey = serialization.load_pem_public_key(f.read())
    client = Client(args.username, args.host, args.port, server_pubkey=server_pubkey)
    if args.register:
        password = input("Enter password for registration: ")
        client.register(password)
    else:
        password = input("Enter password: ")
        if client.login(password):
            client.run()
