#!/usr/bin/env python3
"""
WireGuard Gaming Panel - Backend Server
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
import base64
import socket
import time
import os

app = Flask(__name__, static_folder=None)
CORS(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def b64_to_bytes(s):
    return base64.b64decode(s)


def bytes_to_b64(b):
    return base64.b64encode(b).decode("ascii")


@app.route("/")
def serve_panel():
    return send_from_directory(BASE_DIR, "panel.html")


@app.route("/wg/derive-pubkey", methods=["POST", "OPTIONS"])
def derive_pubkey():
    if request.method == "OPTIONS":
        return "", 204
    try:
        data = request.get_json(force=True)
        priv_b64 = data.get("privateKey", "")
        if not priv_b64:
            return jsonify({"error": "privateKey missing"}), 400
        priv_bytes = b64_to_bytes(priv_b64)
        if len(priv_bytes) != 32:
            return jsonify({"error": "privateKey must be 32 bytes"}), 400
        priv = X25519PrivateKey.from_private_bytes(priv_bytes)
        pub = priv.public_key()
        pub_bytes = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return jsonify({"publicKey": bytes_to_b64(pub_bytes)})
    except Exception as e:
        print("[derive-pubkey] error:", type(e).__name__)
        return jsonify({"error": "derivation failed"}), 500


@app.route("/wg/health", methods=["POST", "OPTIONS"])
def health():
    if request.method == "OPTIONS":
        return "", 204
    try:
        data = request.get_json(force=True)
        host = data.get("host")
        port = int(data.get("port", 0))
        if not host or not (1 <= port <= 65535):
            return jsonify({"error": "invalid host/port"}), 400
        t0 = time.time()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        try:
            s.connect((host, port))
            latency = int((time.time() - t0) * 1000)
            s.close()
            return jsonify({"status": "online", "latencyMs": latency, "packetLoss": 0})
        except Exception:
            try:
                s.close()
            except Exception:
                pass
            return jsonify({"status": "offline", "latencyMs": None, "packetLoss": None})
    except Exception as e:
        print("[health] error:", type(e).__name__)
        return jsonify({"error": "health check failed"}), 500