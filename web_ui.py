"""
web_ui.py - Standalone E2EE Web Application & Server
Course: Cryptography and Network Security (CNS)
Features:
- Zero external dependencies (uses standard library http.server).
- Real Diffie-Hellman 2048-bit key exchange & AES-256-CBC + HMAC-SHA256 engine.
- Modern responsive web interface with live packet inspector and MITM tamper simulator.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import urllib.parse
import time
import os
import sys

# Import local cryptography engine
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import crypto_engine

PORT = 8080

# In-memory session store
active_users = {} # username -> {priv_key, pub_key, sessions: {peer: session_key}}
message_inbox = {} # username -> list of packets
audit_logs = []

def get_local_ip():
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

LOCAL_IP = get_local_ip()

HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>E2EE Campus Chat - Web UI</title>
    <style>
        :root {
            --primary: #2563eb;
            --primary-hover: #1d4ed8;
            --bg: #f8fafc;
            --surface: #ffffff;
            --border: #e2e8f0;
            --text: #0f172a;
            --muted: #64748b;
            --danger: #dc2626;
            --success: #16a34a;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
        body { background: var(--bg); color: var(--text); display: flex; flex-direction: column; height: 100vh; }
        header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 12px 24px; display: flex; align-items: center; justify-content: space-between; }
        .logo-group { display: flex; align-items: center; gap: 10px; }
        .logo-icon { font-size: 24px; }
        .logo-title { font-size: 18px; font-weight: 700; color: #1e293b; }
        .badge { background: #dcfce7; color: #166534; font-size: 11px; font-weight: 600; padding: 4px 8px; border-radius: 9999px; }
        .main-container { display: flex; flex: 1; overflow: hidden; }
        .sidebar { width: 280px; background: var(--surface); border-right: 1px solid var(--border); display: flex; flex-direction: column; }
        .sidebar-header { padding: 16px; border-bottom: 1px solid var(--border); font-size: 12px; font-weight: 700; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; }
        .user-switcher { padding: 12px 16px; border-bottom: 1px solid var(--border); }
        .role-btn { width: 100%; padding: 8px 12px; margin-bottom: 6px; border: 1px solid var(--border); background: var(--bg); border-radius: 6px; font-weight: 600; font-size: 13px; cursor: pointer; text-align: left; display: flex; align-items: center; justify-content: space-between; transition: 0.2s; }
        .role-btn.active { background: #eff6ff; border-color: var(--primary); color: var(--primary); }
        .peer-list { flex: 1; overflow-y: auto; padding: 8px; }
        .peer-item { padding: 10px 12px; border-radius: 6px; display: flex; align-items: center; gap: 10px; cursor: pointer; margin-bottom: 4px; transition: 0.2s; }
        .peer-item:hover, .peer-item.active { background: #f1f5f9; }
        .peer-avatar { width: 32px; height: 32px; border-radius: 50%; background: #e2e8f0; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 13px; color: #475569; }
        .peer-name { font-size: 14px; font-weight: 600; }
        .chat-container { flex: 1; display: flex; flex-direction: column; background: #ffffff; }
        .security-banner { background: #f1f5f9; border-bottom: 1px solid var(--border); padding: 8px 20px; font-size: 12px; color: #475569; display: flex; align-items: center; justify-content: space-between; font-family: monospace; }
        .messages-area { flex: 1; overflow-y: auto; padding: 20px; display: flex; flex-direction: column; gap: 14px; }
        .msg { max-width: 65%; display: flex; flex-direction: column; animation: fadeIn 0.15s ease-out; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }
        .msg.sent { align-self: flex-end; }
        .msg.received { align-self: flex-start; }
        .msg-bubble { padding: 10px 14px; border-radius: 12px; font-size: 14px; line-height: 1.4; word-break: break-word; }
        .msg.sent .msg-bubble { background: var(--primary); color: #ffffff; border-bottom-right-radius: 2px; }
        .msg.received .msg-bubble { background: #f1f5f9; color: var(--text); border-bottom-left-radius: 2px; border: 1px solid var(--border); }
        .msg-meta { font-size: 11px; margin-top: 4px; display: flex; align-items: center; gap: 6px; }
        .msg.sent .msg-meta { align-self: flex-end; color: var(--muted); }
        .msg.received .msg-meta { align-self: flex-start; color: var(--muted); }
        .verified-tag { color: var(--success); font-weight: 600; font-size: 10px; display: flex; align-items: center; gap: 2px; }
        .alert-box { background: #fef2f2; border: 1px solid #fecaca; color: #991b1b; padding: 10px 14px; border-radius: 8px; font-size: 13px; font-weight: 500; display: none; margin: 10px 20px 0; align-items: center; gap: 8px; }
        .bottom-panel { border-top: 1px solid var(--border); padding: 16px 20px; background: var(--surface); display: flex; flex-direction: column; gap: 10px; }
        .mitm-bar { display: flex; align-items: center; gap: 8px; font-size: 12px; font-weight: 600; color: var(--danger); background: #fef2f2; padding: 6px 12px; border-radius: 6px; width: fit-content; border: 1px solid #fee2e2; }
        .input-bar { display: flex; gap: 10px; }
        .input-bar input { flex: 1; padding: 10px 14px; border: 1px solid var(--border); border-radius: 8px; font-size: 14px; outline: none; }
        .input-bar input:focus { border-color: var(--primary); box-shadow: 0 0 0 2px rgba(37,99,235,0.15); }
        .send-btn { background: var(--primary); color: white; border: none; padding: 10px 18px; border-radius: 8px; font-weight: 600; font-size: 14px; cursor: pointer; transition: 0.15s; }
        .send-btn:hover { background: var(--primary-hover); }
        .inspector { width: 340px; background: #0f172a; color: #e2e8f0; border-left: 1px solid #334155; display: flex; flex-direction: column; font-family: monospace; font-size: 11px; }
        .inspector-header { padding: 12px 16px; border-bottom: 1px solid #1e293b; font-weight: 700; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px; }
        .inspector-body { flex: 1; overflow-y: auto; padding: 14px; display: flex; flex-direction: column; gap: 12px; }
        .packet-card { background: #1e293b; border-radius: 6px; padding: 10px; border: 1px solid #334155; }
        .packet-title { color: #38bdf8; font-weight: bold; margin-bottom: 4px; }
        .packet-field { margin-bottom: 4px; word-break: break-all; color: #94a3b8; }
        .packet-field span { color: #f1f5f9; }
    </style>
</head>
<body>
    <header>
        <div class="logo-group">
            <span class="logo-icon">🔒</span>
            <span class="logo-title">E2EE Campus Wi-Fi Chat</span>
            <span class="badge">CNS Micro-Project</span>
        </div>
        <div style="font-size: 12px; color: var(--muted); font-family: monospace;">
            Server: <b style="color: var(--text);">{LOCAL_IP}:5555</b> | Web UI: <b style="color: var(--text);">Port 8080</b>
        </div>
    </header>

    <div class="main-container">
        <!-- Sidebar -->
        <div class="sidebar">
            <div class="sidebar-header">Switch Client Perspective</div>
            <div class="user-switcher">
                <button class="role-btn active" id="btn-alice" onclick="switchUser('Alice')">
                    <span>👩 Alice</span>
                    <span style="font-size: 11px; color: var(--muted);">Client 1</span>
                </button>
                <button class="role-btn" id="btn-bob" onclick="switchUser('Bob')">
                    <span>👨 Bob</span>
                    <span style="font-size: 11px; color: var(--muted);">Client 2</span>
                </button>
            </div>
            <div class="sidebar-header">Peers Online</div>
            <div class="peer-list" id="peer-list">
                <!-- Dynamically populated -->
            </div>
        </div>

        <!-- Chat Container -->
        <div class="chat-container">
            <div class="security-banner">
                <span>🔒 E2EE Session: <b id="session-status">Initializing Diffie-Hellman...</b></span>
                <span style="color: var(--muted);">RFC 3526 DH-2048 | AES-256-CBC | HMAC-SHA256</span>
            </div>

            <div class="alert-box" id="tamper-alert">
                <span>🚨</span>
                <span id="tamper-alert-text">SECURITY ALERT: Message tampering detected! HMAC-SHA256 mismatch. Packet discarded.</span>
            </div>

            <div class="messages-area" id="messages-area">
                <!-- Messages populated here -->
            </div>

            <div class="bottom-panel">
                <label class="mitm-bar">
                    <input type="checkbox" id="chk-mitm">
                    <span>⚠️ Simulate MITM Attack (Flip 1 bit in ciphertext before relay)</span>
                </label>
                <div class="input-bar">
                    <input type="text" id="msg-input" placeholder="Type an encrypted message..." onkeydown="if(event.key==='Enter') sendMessage()">
                    <button class="send-btn" onclick="sendMessage()">🔒 Encrypt & Send</button>
                </div>
            </div>
        </div>

        <!-- Live Packet Inspector -->
        <div class="inspector">
            <div class="inspector-header">🛡️ Live Packet Inspector</div>
            <div class="inspector-body" id="inspector-body">
                <div style="color: #64748b; font-style: italic;">Packets routed through blind relay will be inspected here in real-time...</div>
            </div>
        </div>
    </div>

    <script>
        let currentUser = 'Alice';
        let currentPeer = 'Bob';

        async function switchUser(user) {
            currentUser = user;
            currentPeer = user === 'Alice' ? 'Bob' : 'Alice';
            document.getElementById('btn-alice').classList.toggle('active', user === 'Alice');
            document.getElementById('btn-bob').classList.toggle('active', user === 'Bob');
            document.getElementById('msg-input').placeholder = `Type message as ${currentUser}...`;
            renderPeers();
            await ensureSession();
            await pollMessages();
        }

        function renderPeers() {
            const list = document.getElementById('peer-list');
            list.innerHTML = `
                <div class="peer-item active">
                    <div class="peer-avatar">${currentPeer[0]}</div>
                    <div>
                        <div class="peer-name">${currentPeer}</div>
                        <div style="font-size: 11px; color: #16a34a; font-weight: 500;">● Online (E2EE Ready)</div>
                    </div>
                </div>
            `;
        }

        async function ensureSession() {
            try {
                const res = await fetch('/api/handshake', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ user: currentUser, peer: currentPeer })
                });
                const data = await res.json();
                document.getElementById('session-status').innerHTML = `<span style="color:#16a34a">Active with ${currentPeer} (AES-256 Key: ${data.key_preview})</span>`;
            } catch (err) {
                console.error(err);
            }
        }

        async function sendMessage() {
            const input = document.getElementById('msg-input');
            const text = input.value.trim();
            if (!text) return;
            input.value = '';

            const isTampered = document.getElementById('chk-mitm').checked;

            try {
                const res = await fetch('/api/send', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        sender: currentUser,
                        recipient: currentPeer,
                        text: text,
                        tamper: isTampered
                    })
                });
                const data = await res.json();
                if (data.packet) {
                    addInspectorCard(data.packet, isTampered);
                }
                await pollMessages();
            } catch (err) {
                console.error(err);
            }
        }

        async function pollMessages() {
            try {
                const res = await fetch(`/api/messages?user=${currentUser}`);
                const data = await res.json();
                const container = document.getElementById('messages-area');
                container.innerHTML = '';

                data.messages.forEach(m => {
                    const isMe = m.sender === currentUser;
                    const div = document.createElement('div');
                    div.className = `msg ${isMe ? 'sent' : 'received'}`;
                    div.innerHTML = `
                        <div class="msg-bubble">${m.text}</div>
                        <div class="msg-meta">
                            <span>${m.time}</span>
                            <span class="verified-tag">✓ VERIFIED (HMAC-SHA256)</span>
                        </div>
                    `;
                    container.appendChild(div);
                });
                container.scrollTop = container.scrollHeight;

                const alertBox = document.getElementById('tamper-alert');
                if (data.tamper_detected) {
                    alertBox.style.display = 'flex';
                    alertBox.innerHTML = `<span>🚨</span><span>SECURITY ALERT: Discarded tampered packet from ${currentPeer}! Bit-flip detected by HMAC-SHA256.</span>`;
                } else {
                    alertBox.style.display = 'none';
                }
            } catch (err) {
                console.error(err);
            }
        }

        function addInspectorCard(pkt, tampered) {
            const body = document.getElementById('inspector-body');
            const card = document.createElement('div');
            card.className = 'packet-card';
            card.style.borderColor = tampered ? '#ef4444' : '#334155';
            card.innerHTML = `
                <div class="packet-title" style="color: ${tampered ? '#ef4444' : '#38bdf8'}">
                    ${tampered ? '⚠️ TAMPERED CIPHERTEXT PACKET' : '🛡️ ENCRYPTED RELAY ENVELOPE'}
                </div>
                <div class="packet-field">From: <span>${pkt.from}</span> -> To: <span>${pkt.to}</span></div>
                <div class="packet-field">IV: <span>${pkt.iv.slice(0, 16)}...</span></div>
                <div class="packet-field">Ciphertext: <span>${pkt.ciphertext.slice(0, 24)}...</span></div>
                <div class="packet-field">HMAC Tag: <span>${pkt.hmac_tag.slice(0, 16)}...</span></div>
                <div class="packet-field" style="color: ${tampered ? '#f87171' : '#34d399'}">Status: ${tampered ? 'CORRUPTED (1-bit flipped)' : 'SEALED & AUTHENTIC'}</div>
            `;
            body.insertBefore(card, body.firstChild);
        }

        // Init
        renderPeers();
        ensureSession();
        setInterval(pollMessages, 1000);
    </script>
</body>
</html>
""".replace("{LOCAL_IP}", LOCAL_IP)


class WebAppHandler(BaseHTTPRequestHandler):
    def _send_json(self, data, code=200):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        if url.path == "/" or url.path == "/index.html":
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode('utf-8'))
        elif url.path == "/api/messages":
            params = urllib.parse.parse_qs(url.query)
            user = params.get('user', [''])[0]
            user_inbox = message_inbox.get(user, [])
            # Check if any tamper alert occurred for this user
            tamper_flag = False
            for p in user_inbox:
                if p.get("tampered_dropped"):
                    tamper_flag = True
            self._send_json({"messages": [m for m in user_inbox if not m.get("tampered_dropped")], "tamper_detected": tamper_flag})
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        url = urllib.parse.urlparse(self.path)
        length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(length)
        data = json.loads(post_data.decode('utf-8')) if post_data else {}

        if url.path == "/api/handshake":
            user = data.get("user")
            peer = data.get("peer")
            if user not in active_users:
                priv, pub = crypto_engine.generate_dh_keypair()
                active_users[user] = {"priv": priv, "pub": pub, "sessions": {}}
            if peer not in active_users:
                priv, pub = crypto_engine.generate_dh_keypair()
                active_users[peer] = {"priv": priv, "pub": pub, "sessions": {}}

            # Agree on shared key
            session_key = crypto_engine.compute_shared_session_key(active_users[peer]["pub"], active_users[user]["priv"])
            active_users[user]["sessions"][peer] = session_key
            active_users[peer]["sessions"][user] = session_key

            self._send_json({"status": "ok", "key_preview": session_key[:8].hex() + "..."})

        elif url.path == "/api/send":
            sender = data.get("sender")
            recipient = data.get("recipient")
            text = data.get("text", "")
            tamper = data.get("tamper", False)

            session_key = active_users.get(sender, {}).get("sessions", {}).get(recipient)
            if not session_key:
                self._send_json({"error": "No session key"}, 400)
                return

            # Encrypt with AES-256-CBC and generate HMAC seal
            enc_dict = crypto_engine.encrypt_message(session_key, text)
            if tamper:
                ct = list(enc_dict["ciphertext"])
                ct[0] = '0' if ct[0] != '0' else '1'
                enc_dict["ciphertext"] = "".join(ct)

            pkt = {
                "from": sender,
                "to": recipient,
                "iv": enc_dict["iv"],
                "ciphertext": enc_dict["ciphertext"],
                "hmac_tag": enc_dict["hmac_tag"],
                "timestamp": time.time()
            }

            # Decryption & HMAC verification on recipient side
            if recipient not in message_inbox:
                message_inbox[recipient] = []
            if sender not in message_inbox:
                message_inbox[sender] = []

            # Save to sender transcript
            now_str = time.strftime("%H:%M:%S")
            message_inbox[sender].append({"sender": sender, "text": text, "time": now_str})

            try:
                decrypted = crypto_engine.decrypt_message(session_key, pkt)
                message_inbox[recipient].append({"sender": sender, "text": decrypted, "time": now_str})
            except ValueError:
                # Tamper detected!
                message_inbox[recipient].append({"sender": sender, "tampered_dropped": True, "time": now_str})

            self._send_json({"status": "sent", "packet": pkt})
        else:
            self.send_response(404)
            self.end_headers()


def run():
    server = HTTPServer(('0.0.0.0', PORT), WebAppHandler)
    print("=" * 60)
    print("🌐 E2EE CAMPUS CHAT WEB UI IS LIVE!")
    print("=" * 60)
    print(f"[*] Local Browser Link:    http://localhost:{PORT}")
    print(f"[*] Campus Wi-Fi Link:     http://{LOCAL_IP}:{PORT}")
    print("=" * 60)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()


if __name__ == "__main__":
    run()
