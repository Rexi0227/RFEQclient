# rfeq_client.py

import requests
import json
import base64
import websocket
import threading
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

class RFEQClient:
    def __init__(self, username, password, server_url='http://RFEQSERVER.myqnapcloud.com', ws_url='ws://RFEQSERVER.myqnapcloud.com', on_message=None):
        self.username = username
        self.password = password
        self.server_url = server_url
        self.ws_url = ws_url
        self.verify_key = None
        self.user = None
        self.key_pair = RSA.generate(2048)
        self.on_message = on_message

    def _request_key(self):
        response = requests.get(f'{self.server_url}:8787/getKey')
        return response.json()

    def _encrypt_with_public_key(self, data: str, pem_key: str):
        key = RSA.import_key(pem_key)
        cipher = PKCS1_OAEP.new(key)
        encrypted = cipher.encrypt(data.encode('utf-8'))
        return base64.b64encode(encrypted).decode('utf-8')

    def _decrypt_with_private_key(self, base64_data: str):
        cipher = PKCS1_OAEP.new(self.key_pair)
        encrypted = base64.b64decode(base64_data)
        return cipher.decrypt(encrypted).decode('utf-8')

    def login(self):
        key_response = self._request_key()
        id = key_response['id']
        server_public_key = key_response['publicKey']

        public_key_pem = self.key_pair.publickey().export_key(format='PEM').decode('utf-8')

        login_payload = json.dumps({
            "username": self.username,
            "password": self.password
        })

        encrypted_data = self._encrypt_with_public_key(login_payload, server_public_key)
        encrypted_client_pubkey = self._encrypt_with_public_key(public_key_pem, server_public_key)

        response = requests.post(f'{self.server_url}:8787/login', json={
            'encryptedData': encrypted_data,
            'publicKeyPEM': encrypted_client_pubkey,
            'id': id
        })

        result = response.json()
        if result['status'] == 'success':
            self.verify_key = self._decrypt_with_private_key(result['verifyKey'])
            self.user = result['username']
            print(f"Login success. Verify key: {self.verify_key}")
            return True
        else:
            print(f"Login failed: {result['status']}")
            return False

    def connect_ws(self):
        if not self.verify_key:
            print("You must login first.")
            return

        def on_message(ws, message):
            data = json.loads(message)
            if data["type"] == "login":
                if data["status"] == "success":
                    print("WebSocket login verified")
                else:
                    print("WebSocket login failed")
            else:
                if self.on_message:
                    self.on_message(data)
        def on_open(ws):
            print("🔌 WebSocket connected, requesting key...")
            ws.send(json.dumps({"request": "getKey"}))

        def on_message_with_verify(ws, message):
            data = json.loads(message)
            if data["type"] == "key":
                server_public_key = data['key']
                encrypted_verify = self._encrypt_with_public_key(self.verify_key, server_public_key)
                ws.send(json.dumps({"request": "verify", "key": encrypted_verify}))
                ws.on_message = on_message

        ws = websocket.WebSocketApp(self.ws_url + ":8788",
                                    on_open=on_open,
                                    on_message=on_message_with_verify)
        threading.Thread(target=ws.run_forever, daemon=True).start()
