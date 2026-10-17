"""
web_ui.py - Standalone E2EE Web Application & Server (Multi-User Hardened)
Course: Cryptography and Network Security (CNS)
Features:
- Zero external dependencies (uses Python standard library ThreadingHTTPServer).
- Real Diffie-Hellman 2048-bit key exchange & AES-256-CBC + HMAC-SHA256 engine.
- Dynamic multi-user peer discovery with 15-second heartbeat registry.
- Clean session-based Display Name onboarding and switching.
- Partitioned per-conversation message storage with zero cross-talk.
- Live Packet Inspector for outbound AND inbound cryptograms.
- Auto-resetting MITM tamper attack simulator with dismissible security alerts.
"""

from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import json
import urllib.parse
import time
import os
import sys
import threading
import socket

# Import local cryptography engine
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import crypto_engine

PORT = 8080

# In-memory thread-safe state
server_lock = threading.Lock()
# active_users: username -> {"priv": priv_key_int, "pub": pub_key_int, "sessions": {peer_username: session_key_bytes}}
active_users = {}
# user_last_seen: username -> float timestamp
user_last_seen = {}
# conversations: (user_a, user_b) sorted tuple -> list of packet/message records
conversations = {}


def get_local_ip():
    """Returns the local network Wi-Fi / LAN IP address for cross-device access."""
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
            --warning: #d97706;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
        body { background: var(--bg); color: var(--text); display: flex; flex-direction: column; height: 100vh; overflow: hidden; }
        
        header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 12px 24px; display: flex; align-items: center; justify-content: space-between; z-index: 10; }
        .logo-group { display: flex; align-items: center; gap: 10px; }
        .logo-icon { font-size: 24px; }
        .logo-title { font-size: 18px; font-weight: 700; color: #1e293b; }
        .badge { background: #dcfce7; color: #166534; font-size: 11px; font-weight: 600; padding: 4px 8px; border-radius: 9999px; }
        
        .header-right { display: flex; align-items: center; gap: 16px; font-size: 13px; }
        .user-identity-chip { background: #f1f5f9; border: 1px solid var(--border); padding: 5px 12px; border-radius: 20px; display: flex; align-items: center; gap: 8px; font-weight: 500; }
        .switch-name-btn { background: none; border: none; color: var(--primary); font-size: 12px; font-weight: 600; cursor: pointer; text-decoration: underline; padding: 0; }
        .switch-name-btn:hover { color: var(--primary-hover); }
        .server-info { font-size: 11px; color: var(--muted); font-family: monospace; }
        
        .main-container { display: flex; flex: 1; overflow: hidden; }
        
        /* Left Sidebar */
        .sidebar { width: 280px; background: var(--surface); border-right: 1px solid var(--border); display: flex; flex-direction: column; }
        .sidebar-section-title { padding: 14px 16px 8px; font-size: 11px; font-weight: 700; color: var(--muted); text-transform: uppercase; letter-spacing: 0.6px; }
        .my-card { margin: 8px 12px 14px; padding: 10px 12px; background: #f8fafc; border: 1px solid var(--border); border-radius: 8px; display: flex; align-items: center; gap: 10px; }
        .my-avatar { width: 36px; height: 36px; border-radius: 50%; background: #2563eb; color: white; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 15px; }
        .my-details { display: flex; flex-direction: column; }
        .my-name { font-weight: 700; font-size: 14px; color: #1e293b; }
        .my-status { font-size: 11px; color: var(--success); font-weight: 600; display: flex; align-items: center; gap: 4px; }
        
        .peer-list { flex: 1; overflow-y: auto; padding: 0 10px 12px; }
        .peer-item { padding: 10px 12px; border-radius: 8px; display: flex; align-items: center; gap: 10px; cursor: pointer; margin-bottom: 6px; border: 1px solid transparent; transition: 0.15s ease-in-out; }
        .peer-item:hover { background: #f1f5f9; }
        .peer-item.active { background: #eff6ff; border-color: #bfdbfe; }
        .peer-avatar { width: 34px; height: 34px; border-radius: 50%; background: #e2e8f0; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 13px; color: #475569; }
        .peer-item.active .peer-avatar { background: #2563eb; color: white; }
        .peer-name { font-size: 14px; font-weight: 600; }
        .peer-status { font-size: 11px; color: #16a34a; font-weight: 500; }
        .empty-peers { text-align: center; padding: 30px 16px; color: var(--muted); font-size: 13px; line-height: 1.5; }
        
        /* Chat Feed */
        .chat-container { flex: 1; display: flex; flex-direction: column; background: #ffffff; min-width: 0; }
        .security-banner { background: #f1f5f9; border-bottom: 1px solid var(--border); padding: 8px 20px; font-size: 12px; color: #475569; display: flex; align-items: center; justify-content: space-between; font-family: monospace; }
        
        .alert-box { background: #fef2f2; border: 1px solid #fecaca; color: #991b1b; padding: 10px 16px; border-radius: 8px; font-size: 13px; font-weight: 500; display: none; margin: 10px 20px 0; align-items: center; justify-content: space-between; animation: slideDown 0.2s ease-out; }
        @keyframes slideDown { from { opacity: 0; transform: translateY(-6px); } to { opacity: 1; transform: translateY(0); } }
        .dismiss-alert-btn { background: #fee2e2; border: 1px solid #fca5a5; color: #991b1b; font-size: 11px; font-weight: 700; padding: 4px 10px; border-radius: 6px; cursor: pointer; transition: 0.15s; }
        .dismiss-alert-btn:hover { background: #fecaca; }
        
        .messages-area { flex: 1; overflow-y: auto; padding: 20px; display: flex; flex-direction: column; gap: 14px; }
        .no-chat-selected { margin: auto; text-align: center; color: var(--muted); max-width: 380px; line-height: 1.6; font-size: 14px; }
        
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
        
        .bottom-panel { border-top: 1px solid var(--border); padding: 14px 20px; background: var(--surface); display: flex; flex-direction: column; gap: 10px; }
        .mitm-bar-row { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
        .mitm-bar { display: flex; align-items: center; gap: 8px; font-size: 12px; font-weight: 600; color: var(--danger); background: #fef2f2; padding: 6px 12px; border-radius: 6px; width: fit-content; border: 1px solid #fee2e2; cursor: pointer; user-select: none; }
        .mitm-notice { display: none; font-size: 12px; font-weight: 600; color: #b91c1c; background: #fff1f2; border: 1px solid #fecdd3; padding: 4px 10px; border-radius: 6px; animation: fadeIn 0.2s; }
        
        .input-bar { display: flex; gap: 10px; }
        .input-bar input { flex: 1; padding: 10px 14px; border: 1px solid var(--border); border-radius: 8px; font-size: 14px; outline: none; transition: 0.15s; }
        .input-bar input:focus { border-color: var(--primary); box-shadow: 0 0 0 2px rgba(37,99,235,0.15); }
        .send-btn { background: var(--primary); color: white; border: none; padding: 10px 20px; border-radius: 8px; font-weight: 600; font-size: 14px; cursor: pointer; transition: 0.15s; white-space: nowrap; }
        .send-btn:hover { background: var(--primary-hover); }
        .send-btn:disabled { background: #94a3b8; cursor: not-allowed; }
        
        /* Live Packet Inspector */
        .inspector { width: 340px; background: #0f172a; color: #e2e8f0; border-left: 1px solid #334155; display: flex; flex-direction: column; font-family: monospace; font-size: 11px; }
        .inspector-header { padding: 12px 16px; border-bottom: 1px solid #1e293b; font-weight: 700; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px; display: flex; align-items: center; justify-content: space-between; }
        .inspector-body { flex: 1; overflow-y: auto; padding: 14px; display: flex; flex-direction: column; gap: 12px; }
        .packet-card { background: #1e293b; border-radius: 6px; padding: 10px; border: 1px solid #334155; animation: fadeIn 0.2s ease-out; }
        .packet-title { font-weight: bold; margin-bottom: 5px; font-size: 11px; }
        .packet-field { margin-bottom: 4px; word-break: break-all; color: #94a3b8; }
        .packet-field span { color: #f1f5f9; }
        
        /* Display Name Modal */
        .modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(15, 23, 42, 0.65); backdrop-filter: blur(4px); display: flex; align-items: center; justify-content: center; z-index: 999; }
        .modal-card { background: #ffffff; border-radius: 12px; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.2); width: 100%; max-width: 420px; padding: 28px; text-align: center; }
        .modal-icon { font-size: 42px; margin-bottom: 12px; }
        .modal-title { font-size: 20px; font-weight: 700; color: #0f172a; margin-bottom: 6px; }
        .modal-desc { font-size: 13px; color: var(--muted); margin-bottom: 20px; line-height: 1.5; }
        .modal-input { width: 100%; padding: 12px 14px; border: 1px solid var(--border); border-radius: 8px; font-size: 15px; outline: none; margin-bottom: 10px; }
        .modal-input:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(37,99,235,0.15); }
        .modal-error { color: var(--danger); font-size: 12px; margin-bottom: 12px; font-weight: 600; text-align: left; }
        .modal-btn { width: 100%; background: var(--primary); color: white; border: none; padding: 12px; border-radius: 8px; font-size: 14px; font-weight: 700; cursor: pointer; transition: 0.15s; }
        .modal-btn:hover { background: var(--primary-hover); }
    </style>
</head>
<body>
    <!-- Modal: Display Name Onboarding -->
    <div class="modal-overlay" id="name-modal" style="display: none;">
        <div class="modal-card">
            <div class="modal-icon">🔒</div>
            <h2 class="modal-title">Welcome to E2EE Campus Chat</h2>
            <p class="modal-desc">Enter your display name (or roll number) to register your Diffie-Hellman 2048-bit keypair on the local Wi-Fi relay.</p>
            <input type="text" id="display-name-input" class="modal-input" placeholder="e.g. Alice, Bob, or RollNo" maxlength="25" onkeydown="if(event.key==='Enter') saveDisplayName()">
            <div id="modal-error-text" class="modal-error" style="display: none;">Please enter a valid display name.</div>
            <button class="modal-btn" onclick="saveDisplayName()">Enter Secure Chat</button>
        </div>
    </div>

    <header>
        <div class="logo-group">
            <span class="logo-icon">🔒</span>
            <span class="logo-title">E2EE Campus Wi-Fi Chat</span>
            <span class="badge">CNS Micro-Project</span>
        </div>
        <div class="header-right">
            <div class="user-identity-chip">
                <span>👤</span>
                <span>Logged in as: <strong id="header-username">...</strong></span>
                <button class="switch-name-btn" onclick="openNameModal()">[Switch Name]</button>
            </div>
            <div class="server-info">
                Wi-Fi: <strong style="color: var(--text);">{LOCAL_IP}:{PORT}</strong>
            </div>
        </div>
    </header>

    <div class="main-container">
        <!-- Sidebar -->
        <div class="sidebar">
            <div class="sidebar-section-title">My Identity</div>
            <div class="my-card">
                <div class="my-avatar" id="my-avatar-initial">?</div>
                <div class="my-details">
                    <div class="my-name" id="my-card-name">Student</div>
                    <div class="my-status">● Active on Wi-Fi</div>
                </div>
            </div>

            <div class="sidebar-section-title">
                Peers Online (<span id="peer-count">0</span>)
            </div>
            <div class="peer-list" id="peer-list">
                <!-- Dynamically populated -->
            </div>
        </div>

        <!-- Chat Container -->
        <div class="chat-container">
            <div class="security-banner">
                <span>🔒 E2EE Session: <b id="session-status">Select a peer to initiate Diffie-Hellman handshake</b></span>
                <span style="color: var(--muted);">DH-2048 | AES-256-CBC | HMAC-SHA256</span>
            </div>

            <div class="alert-box" id="tamper-alert">
                <div style="display: flex; align-items: center; gap: 8px;">
                    <span style="font-size: 16px;">🚨</span>
                    <span id="tamper-alert-text">SECURITY ALERT: Message tampering detected! HMAC-SHA256 mismatch. Packet discarded.</span>
                </div>
                <button class="dismiss-alert-btn" onclick="dismissTamperAlert()">✕ Dismiss</button>
            </div>

            <div class="messages-area" id="messages-area">
                <div class="no-chat-selected">
                    <div style="font-size: 32px; margin-bottom: 12px;">👥</div>
                    <h3 style="margin-bottom: 6px; color: #1e293b;">No Peer Selected</h3>
                    <p>Select an online student from the left sidebar to establish a Diffie-Hellman shared session key and start an encrypted conversation.</p>
                </div>
            </div>

            <div class="bottom-panel">
                <div class="mitm-bar-row">
                    <label class="mitm-bar">
                        <input type="checkbox" id="chk-mitm">
                        <span>⚠️ Simulate MITM Attack (Flip 1 bit in ciphertext before relay)</span>
                    </label>
                    <span id="mitm-notice" class="mitm-notice">
                        ⚡ MITM bit-flip applied! Checkbox auto-reset to OFF.
                    </span>
                </div>
                <div class="input-bar">
                    <input type="text" id="msg-input" placeholder="Select an online peer first..." disabled onkeydown="if(event.key==='Enter') sendMessage()">
                    <button class="send-btn" id="send-btn" disabled onclick="sendMessage()">🔒 Encrypt & Send</button>
                </div>
            </div>
        </div>

        <!-- Live Packet Inspector -->
        <div class="inspector">
            <div class="inspector-header">
                <span>🛡️ Live Packet Inspector</span>
                <span style="font-size: 10px; color: #64748b; font-weight: normal;">Live Cryptograms</span>
            </div>
            <div class="inspector-body" id="inspector-body">
                <div id="inspector-empty" style="color: #64748b; font-style: italic; line-height: 1.5;">
                    Packets routed through blind relay will be inspected here in real-time...
                </div>
            </div>
        </div>
    </div>

    <script>
        let currentUser = sessionStorage.getItem('cns_chat_username') || '';
        let currentPeer = null;
        let activeKeyPreview = '';
        let dismissedTamperIds = new Set();
        let renderedPacketKeys = new Set();
        let lastMessageCount = 0;

        function escapeHtml(str) {
            if (!str) return '';
            return String(str)
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }

        function checkUserOnboarding() {
            if (!currentUser) {
                openNameModal();
            } else {
                updateUserUI();
                pollPeers();
                pollMessages();
            }
        }

        function openNameModal() {
            const input = document.getElementById('display-name-input');
            input.value = currentUser || '';
            document.getElementById('modal-error-text').style.display = 'none';
            document.getElementById('name-modal').style.display = 'flex';
            setTimeout(() => input.focus(), 100);
        }

        function saveDisplayName() {
            const input = document.getElementById('display-name-input');
            const name = input.value.trim();
            if (!name) {
                const err = document.getElementById('modal-error-text');
                err.innerText = 'Display name cannot be empty.';
                err.style.display = 'block';
                return;
            }

            const isSwitch = currentUser && currentUser !== name;
            currentUser = name;
            sessionStorage.setItem('cns_chat_username', name);
            document.getElementById('name-modal').style.display = 'none';
            updateUserUI();

            if (isSwitch) {
                currentPeer = null;
                resetChatView();
            }
            pollPeers();
        }

        function updateUserUI() {
            document.getElementById('header-username').innerText = currentUser;
            document.getElementById('my-card-name').innerText = currentUser;
            document.getElementById('my-avatar-initial').innerText = (currentUser[0] || '?').toUpperCase();
        }

        function resetChatView() {
            document.getElementById('session-status').innerHTML = 'Select a peer to initiate Diffie-Hellman handshake';
            document.getElementById('msg-input').placeholder = 'Select an online peer first...';
            document.getElementById('msg-input').disabled = true;
            document.getElementById('send-btn').disabled = true;
            document.getElementById('messages-area').innerHTML = `
                <div class="no-chat-selected">
                    <div style="font-size: 32px; margin-bottom: 12px;">👥</div>
                    <h3 style="margin-bottom: 6px; color: #1e293b;">No Peer Selected</h3>
                    <p>Select an online student from the left sidebar to establish a Diffie-Hellman shared session key and start an encrypted conversation.</p>
                </div>
            `;
            document.getElementById('inspector-body').innerHTML = `
                <div id="inspector-empty" style="color: #64748b; font-style: italic; line-height: 1.5;">
                    Packets routed through blind relay will be inspected here in real-time...
                </div>
            `;
            renderedPacketKeys.clear();
            lastMessageCount = 0;
            document.getElementById('tamper-alert').style.display = 'none';
        }

        async function pollPeers() {
            if (!currentUser) return;
            try {
                const res = await fetch(`/api/peers?user=${encodeURIComponent(currentUser)}`);
                const data = await res.json();
                renderPeers(data.peers || []);
            } catch (err) {
                console.error("Peer poll error:", err);
            }
        }

        function renderPeers(peers) {
            const list = document.getElementById('peer-list');
            document.getElementById('peer-count').innerText = peers.length;

            if (peers.length === 0) {
                list.innerHTML = `
                    <div class="empty-peers">
                        <div style="font-size: 26px; margin-bottom: 8px;">🔍</div>
                        <div style="font-weight: 600; margin-bottom: 4px; color: #334155;">No Other Peers Online</div>
                        <div>Open this link in another browser tab, incognito window, or on another campus device to chat!</div>
                    </div>
                `;
                return;
            }

            // Auto-select first peer if none active
            if (!currentPeer && peers.length > 0) {
                selectPeer(peers[0]);
                return;
            }

            let html = '';
            peers.forEach(p => {
                const isActive = (p === currentPeer);
                html += `
                    <div class="peer-item ${isActive ? 'active' : ''}" onclick="selectPeer('${escapeHtml(p)}')">
                        <div class="peer-avatar">${escapeHtml(p[0].toUpperCase())}</div>
                        <div style="flex: 1; min-width: 0;">
                            <div class="peer-name">${escapeHtml(p)}</div>
                            <div class="peer-status">● Online (E2EE Ready)</div>
                        </div>
                    </div>
                `;
            });
            list.innerHTML = html;
        }

        async function selectPeer(peer) {
            if (currentPeer === peer) return;
            currentPeer = peer;
            pollPeers(); // re-render sidebar selection
            document.getElementById('msg-input').disabled = false;
            document.getElementById('send-btn').disabled = false;
            document.getElementById('msg-input').placeholder = `Type an encrypted message to ${peer}...`;
            document.getElementById('msg-input').focus();

            // Clear inspector for new peer view
            document.getElementById('inspector-body').innerHTML = `
                <div id="inspector-empty" style="color: #64748b; font-style: italic; line-height: 1.5;">
                    Inspecting cryptograms for conversation with ${escapeHtml(peer)}...
                </div>
            `;
            renderedPacketKeys.clear();
            lastMessageCount = 0;
            document.getElementById('tamper-alert').style.display = 'none';

            await ensureSession();
            await pollMessages();
        }

        async function ensureSession() {
            if (!currentPeer || !currentUser) return;
            try {
                const res = await fetch('/api/handshake', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ user: currentUser, peer: currentPeer })
                });
                const data = await res.json();
                activeKeyPreview = data.key_preview || '';
                document.getElementById('session-status').innerHTML = `
                    <span style="color:#16a34a">Active with ${escapeHtml(currentPeer)}</span> 
                    <span style="color:#64748b">(AES-256 Key: ${escapeHtml(activeKeyPreview)})</span>
                `;
            } catch (err) {
                console.error("Handshake error:", err);
            }
        }

        async function sendMessage() {
            const input = document.getElementById('msg-input');
            const text = input.value.trim();
            if (!text || !currentPeer || !currentUser) return;

            const chkMitm = document.getElementById('chk-mitm');
            const isTampered = chkMitm.checked;

            if (isTampered) {
                // Auto-reset checkbox immediately after sending
                chkMitm.checked = false;
                const notice = document.getElementById('mitm-notice');
                notice.style.display = 'inline-block';
                setTimeout(() => { notice.style.display = 'none'; }, 4500);
            }

            input.value = '';

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
                    addInspectorCard(data.packet);
                }
                await pollMessages();
            } catch (err) {
                console.error("Send error:", err);
            }
        }

        async function pollMessages() {
            if (!currentUser || !currentPeer) return;
            try {
                const res = await fetch(`/api/messages?user=${encodeURIComponent(currentUser)}&peer=${encodeURIComponent(currentPeer)}`);
                const data = await res.json();

                // Render Messages
                const container = document.getElementById('messages-area');
                const messages = data.messages || [];

                if (messages.length === 0) {
                    container.innerHTML = `
                        <div style="margin: auto; text-align: center; color: var(--muted); font-size: 13px; max-width: 340px;">
                            <div style="font-size: 24px; margin-bottom: 6px;">🔒</div>
                            <div style="font-weight: 600; margin-bottom: 4px; color: #334155;">End-to-End Encrypted Session Active</div>
                            <div>No messages yet with <b>${escapeHtml(currentPeer)}</b>. Type below to exchange encrypted packets.</div>
                        </div>
                    `;
                    lastMessageCount = 0;
                } else {
                    let html = '';
                    messages.forEach(m => {
                        const isMe = (m.sender === currentUser);
                        html += `
                            <div class="msg ${isMe ? 'sent' : 'received'}">
                                <div class="msg-bubble">${escapeHtml(m.text)}</div>
                                <div class="msg-meta">
                                    <span>${escapeHtml(m.time)}</span>
                                    <span class="verified-tag">✓ VERIFIED (HMAC-SHA256)</span>
                                </div>
                            </div>
                        `;
                    });
                    container.innerHTML = html;
                    if (messages.length !== lastMessageCount) {
                        container.scrollTop = container.scrollHeight;
                        lastMessageCount = messages.length;
                    }
                }

                // Render Packets in Live Inspector (both sent and received)
                if (data.packets && data.packets.length > 0) {
                    data.packets.forEach(pkt => addInspectorCard(pkt));
                }

                // Handle Tamper Alert (dismissible)
                const alertBox = document.getElementById('tamper-alert');
                if (data.tamper_detected && data.tamper_info) {
                    const alertId = data.tamper_info.id;
                    if (!dismissedTamperIds.has(alertId)) {
                        alertBox.style.display = 'flex';
                        document.getElementById('tamper-alert-text').innerText = 
                            `SECURITY ALERT: Discarded tampered packet from ${data.tamper_info.sender}! Alteration detected by HMAC-SHA256 seal at ${data.tamper_info.time}.`;
                        alertBox.dataset.alertId = alertId;
                    } else {
                        alertBox.style.display = 'none';
                    }
                } else {
                    alertBox.style.display = 'none';
                }
            } catch (err) {
                console.error("Message poll error:", err);
            }
        }

        function dismissTamperAlert() {
            const alertBox = document.getElementById('tamper-alert');
            const alertId = alertBox.dataset.alertId;
            if (alertId) {
                dismissedTamperIds.add(alertId);
            }
            alertBox.style.display = 'none';
        }

        function addInspectorCard(pkt) {
            const key = (pkt.iv || '') + (pkt.ciphertext || '').slice(0, 32) + (pkt.timestamp || '');
            if (renderedPacketKeys.has(key)) return;
            renderedPacketKeys.add(key);

            const emptyNotice = document.getElementById('inspector-empty');
            if (emptyNotice) emptyNotice.style.display = 'none';

            const body = document.getElementById('inspector-body');
            const isMe = (pkt.from === currentUser);
            const isTampered = !!pkt.tampered;

            const card = document.createElement('div');
            card.className = 'packet-card';
            card.style.borderColor = isTampered ? '#ef4444' : (isMe ? '#3b82f6' : '#10b981');

            card.innerHTML = `
                <div class="packet-title" style="color: ${isTampered ? '#ef4444' : (isMe ? '#38bdf8' : '#34d399')}">
                    ${isTampered ? '⚠️ TAMPERED CIPHERTEXT PACKET' : (isMe ? '🛡️ ENCRYPTED ENVELOPE (Outbound)' : '🛡️ ENCRYPTED ENVELOPE (Inbound)')}
                </div>
                <div class="packet-field">From: <span>${escapeHtml(pkt.from)}</span> &rarr; To: <span>${escapeHtml(pkt.to)}</span></div>
                <div class="packet-field">IV: <span>${escapeHtml((pkt.iv || '').slice(0, 16))}...</span></div>
                <div class="packet-field">Ciphertext: <span>${escapeHtml((pkt.ciphertext || '').slice(0, 24))}...</span></div>
                <div class="packet-field">HMAC Tag: <span>${escapeHtml((pkt.hmac_tag || '').slice(0, 16))}...</span></div>
                <div class="packet-field" style="color: ${isTampered ? '#f87171' : '#34d399'}; font-weight: bold;">
                    Status: ${isTampered ? 'CORRUPTED (1-bit flipped / Dropped)' : 'AUTHENTIC (HMAC-SHA256 Sealed)'}
                </div>
            `;
            body.insertBefore(card, body.firstChild);
        }

        // Initialize application lifecycle
        checkUserOnboarding();
        setInterval(pollPeers, 3000);
        setInterval(pollMessages, 1000);
    </script>
</body>
</html>
""".replace("{LOCAL_IP}", LOCAL_IP).replace("{PORT}", str(PORT))


class WebAppHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        # Suppress noisy standard HTTP access logs during high-volume polling
        pass

    def _send_json(self, data, code=200):
        self.close_connection = True
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        if url.path == "/" or url.path == "/index.html":
            self.close_connection = True
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode('utf-8'))

        elif url.path == "/api/peers":
            params = urllib.parse.parse_qs(url.query)
            user = params.get('user', [''])[0].strip()
            with server_lock:
                now = time.time()
                if user:
                    user_last_seen[user] = now
                    if user not in active_users:
                        priv, pub = crypto_engine.generate_dh_keypair()
                        active_users[user] = {"priv": priv, "pub": pub, "sessions": {}}

                # 15-second active window
                peers = [
                    u for u, t in user_last_seen.items()
                    if u != user and (now - t) <= 15
                ]
            self._send_json({"peers": peers})

        elif url.path == "/api/messages":
            params = urllib.parse.parse_qs(url.query)
            user = params.get('user', [''])[0].strip()
            peer = params.get('peer', [''])[0].strip()

            with server_lock:
                now = time.time()
                if user:
                    user_last_seen[user] = now

                if not user or not peer:
                    self._send_json({"messages": [], "packets": [], "tamper_detected": False, "tamper_info": None})
                    return

                # Strict per-conversation partitioning
                conv_key = tuple(sorted([user, peer]))
                conv_list = conversations.get(conv_key, [])

                messages_out = []
                packets_out = []
                tamper_detected = False
                tamper_info = None

                for item in conv_list:
                    if "packet" in item:
                        packets_out.append(item["packet"])
                    if item.get("tampered_dropped"):
                        # If I am recipient, alert me that sender's packet was tampered
                        if item.get("recipient") == user:
                            tamper_detected = True
                            tamper_info = {
                                "id": item["id"],
                                "sender": item.get("sender"),
                                "time": item.get("time"),
                                "error": item.get("error", "HMAC verification failed")
                            }
                    else:
                        messages_out.append({
                            "id": item["id"],
                            "sender": item["sender"],
                            "recipient": item["recipient"],
                            "text": item["text"],
                            "time": item["time"]
                        })

            self._send_json({
                "messages": messages_out,
                "packets": packets_out,
                "tamper_detected": tamper_detected,
                "tamper_info": tamper_info
            })
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        url = urllib.parse.urlparse(self.path)
        length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(length)
        data = json.loads(post_data.decode('utf-8')) if post_data else {}

        if url.path == "/api/handshake":
            user = data.get("user", "").strip()
            peer = data.get("peer", "").strip()
            if not user or not peer:
                self._send_json({"error": "Missing user or peer"}, 400)
                return

            with server_lock:
                if user not in active_users:
                    priv, pub = crypto_engine.generate_dh_keypair()
                    active_users[user] = {"priv": priv, "pub": pub, "sessions": {}}
                if peer not in active_users:
                    priv, pub = crypto_engine.generate_dh_keypair()
                    active_users[peer] = {"priv": priv, "pub": pub, "sessions": {}}

                # Derive 256-bit AES shared session key
                if peer not in active_users[user]["sessions"]:
                    session_key = crypto_engine.compute_shared_session_key(
                        active_users[peer]["pub"], active_users[user]["priv"]
                    )
                    active_users[user]["sessions"][peer] = session_key
                    active_users[peer]["sessions"][user] = session_key
                else:
                    session_key = active_users[user]["sessions"][peer]

            self._send_json({"status": "ok", "key_preview": session_key[:8].hex() + "..."})

        elif url.path == "/api/send":
            sender = data.get("sender", "").strip()
            recipient = data.get("recipient", "").strip()
            text = data.get("text", "")
            tamper = bool(data.get("tamper", False))

            if not sender or not recipient:
                self._send_json({"error": "Missing sender or recipient"}, 400)
                return

            with server_lock:
                now = time.time()
                user_last_seen[sender] = now

                if sender not in active_users:
                    priv, pub = crypto_engine.generate_dh_keypair()
                    active_users[sender] = {"priv": priv, "pub": pub, "sessions": {}}
                if recipient not in active_users:
                    priv, pub = crypto_engine.generate_dh_keypair()
                    active_users[recipient] = {"priv": priv, "pub": pub, "sessions": {}}

                session_key = active_users[sender]["sessions"].get(recipient)
                if not session_key:
                    session_key = crypto_engine.compute_shared_session_key(
                        active_users[recipient]["pub"], active_users[sender]["priv"]
                    )
                    active_users[sender]["sessions"][recipient] = session_key
                    active_users[recipient]["sessions"][sender] = session_key

                # Encrypt with AES-256-CBC and generate HMAC-SHA256 seal
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
                    "timestamp": now,
                    "tampered": tamper
                }

                conv_key = tuple(sorted([sender, recipient]))
                if conv_key not in conversations:
                    conversations[conv_key] = []

                now_str = time.strftime("%H:%M:%S")

                # Verify integrity via recipient decryption
                try:
                    decrypted = crypto_engine.decrypt_message(session_key, pkt)
                    record = {
                        "id": len(conversations[conv_key]) + 1,
                        "sender": sender,
                        "recipient": recipient,
                        "text": decrypted,
                        "time": now_str,
                        "packet": pkt,
                        "tampered_dropped": False
                    }
                    conversations[conv_key].append(record)
                except ValueError as e:
                    # Tampering detected!
                    record = {
                        "id": len(conversations[conv_key]) + 1,
                        "sender": sender,
                        "recipient": recipient,
                        "tampered_dropped": True,
                        "error": str(e),
                        "time": now_str,
                        "packet": pkt
                    }
                    conversations[conv_key].append(record)

            self._send_json({"status": "sent", "packet": pkt})
        else:
            self.send_response(404)
            self.end_headers()


def run():
    ThreadingHTTPServer.allow_reuse_address = True
    ThreadingHTTPServer.request_queue_size = 64
    server = ThreadingHTTPServer(('0.0.0.0', PORT), WebAppHandler)
    server.daemon_threads = True
    print("=" * 60)
    print("🌐 E2EE CAMPUS CHAT MULTI-USER WEB UI IS LIVE!")
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
