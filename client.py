"""
client.py - End-to-End Encrypted (E2EE) Desktop Chat Client (Hardened & Reviewed)
Course: Cryptography and Network Security (CNS)

Role:
Operated by Client Nodes (Alice & Bob). Connects to Server IP on local network.
Executes client-side Diffie-Hellman key exchange, AES-256 payload encryption,
and HMAC-SHA256 integrity verification. Includes a live MITM tamper demonstration toggle.

Hardened Features:
- Non-blocking asynchronous socket connection (GUI NEVER freezes if server is offline).
- Byte-level TCP stream framing using b"\\n" (safe against UTF-8 chunk splits).
- Safe window teardown (prevents TclError on app destruction).
- Handshake debouncing guard (prevents race conditions from rapid clicking).
- Automatic message queueing: typing before handshake automatically exchanges keys and sends.
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import threading
import json
import time
import datetime
import sys
import os
import getpass

# Import local cryptography engine
try:
    import crypto_engine
except ImportError:
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    import crypto_engine

MAX_FRAME_SIZE = 65536


class SecureChatClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("E2EE Campus Chat - CNS Micro-Project")
        self.root.geometry("720x680")
        self.root.minsize(640, 580)
        self.root.configure(bg="#F1F5F9")

        # Network & Crypto State
        self.sock = None
        self.is_connected = False
        self.is_connecting = False
        self.is_destroyed = False
        self.username = ""
        self.active_peer = None      # currently selected peer for isolated chat view
        self.conversations = {}      # peer_username -> list of (tag, header_with_time, body)
        self.system_history = []     # list of (tag, header_with_time, body) for connection events
        self.my_private_dh = None
        self.my_public_dh = None
        self.peer_sessions = {}      # peer_username -> 32-byte AES session key
        self.pending_outbox = {}     # peer_username -> list of queued plaintexts
        self.pending_handshakes = set() # debouncing set for in-flight DH handshakes
        self.unread_peers = set()    # peer_username set with unread messages
        self.last_user_list = []     # cached list of online users from server

        # Setup GUI Elements
        self._setup_styles()
        self._build_top_connection_panel()
        self._build_security_status_banner()
        self._build_chat_area()
        self._build_input_and_demo_panel()

        # Handle window close cleanly
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def safe_after(self, delay_ms, callback, *args):
        """Safely invokes callback on main thread if application is not destroyed."""
        if not self.is_destroyed:
            try:
                self.root.after(delay_ms, callback, *args)
            except Exception:
                pass

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TLabel", background="#F1F5F9", font=("Helvetica", 10))
        style.configure("TButton", font=("Helvetica", 10, "bold"), padding=5)

    def _build_top_connection_panel(self):
        conn_frame = tk.LabelFrame(
            self.root, text=" 1. College Wi-Fi Socket Connection ",
            bg="#FFFFFF", fg="#1E293B", font=("Helvetica", 10, "bold"),
            padx=10, pady=8
        )
        conn_frame.pack(fill="x", padx=12, pady=(10, 5))

        tk.Label(conn_frame, text="Server IP:", bg="#FFFFFF", font=("Helvetica", 9, "bold")).grid(row=0, column=0, sticky="w")
        self.ip_entry = tk.Entry(conn_frame, width=15, font=("Consolas", 10))
        self.ip_entry.insert(0, "127.0.0.1")
        self.ip_entry.grid(row=0, column=1, padx=(5, 10))

        tk.Label(conn_frame, text="Port:", bg="#FFFFFF", font=("Helvetica", 9, "bold")).grid(row=0, column=2, sticky="w")
        self.port_entry = tk.Entry(conn_frame, width=6, font=("Consolas", 10))
        self.port_entry.insert(0, "5555")
        self.port_entry.grid(row=0, column=3, padx=(5, 10))

        tk.Label(conn_frame, text="My Username:", bg="#FFFFFF", font=("Helvetica", 9, "bold")).grid(row=0, column=4, sticky="w")
        self.user_entry = tk.Entry(conn_frame, width=12, font=("Helvetica", 10))
        try:
            default_user = getpass.getuser().capitalize() if getpass.getuser() else "Student"
        except Exception:
            default_user = "Student"
        self.user_entry.insert(0, default_user)
        self.user_entry.grid(row=0, column=5, padx=(5, 10))

        self.btn_connect = tk.Button(
            conn_frame, text="Connect", bg="#1E40AF", fg="white",
            font=("Helvetica", 9, "bold"), relief="flat", padx=12, pady=3,
            command=self.toggle_connection
        )
        self.btn_connect.grid(row=0, column=6, padx=5)

    def _build_security_status_banner(self):
        banner_frame = tk.Frame(self.root, bg="#E2E8F0", padx=10, pady=5)
        banner_frame.pack(fill="x", padx=12, pady=4)

        self.status_icon = tk.Label(banner_frame, text="⚪", font=("Helvetica", 12), bg="#E2E8F0")
        self.status_icon.pack(side="left")

        self.status_label = tk.Label(
            banner_frame,
            text="Status: Disconnected. Enter Server IP & Connect.",
            font=("Helvetica", 9, "bold"), fg="#475569", bg="#E2E8F0"
        )
        self.status_label.pack(side="left", padx=5)

        self.cipher_info = tk.Label(
            banner_frame,
            text="Algorithms: Diffie-Hellman 2048 | AES-256-CBC | HMAC-SHA256",
            font=("Consolas", 8), fg="#64748B", bg="#E2E8F0"
        )
        self.cipher_info.pack(side="right")

    def _build_chat_area(self):
        mid_frame = tk.Frame(self.root, bg="#F1F5F9")
        mid_frame.pack(fill="both", expand=True, padx=12, pady=4)

        # Peer selection sidebar
        sidebar = tk.LabelFrame(
            mid_frame, text=" 2. Peers Online ",
            bg="#FFFFFF", fg="#1E293B", font=("Helvetica", 9, "bold"),
            width=170, padx=6, pady=6
        )
        sidebar.pack(side="left", fill="y", padx=(0, 8))
        sidebar.pack_propagate(False)

        self.peer_listbox = tk.Listbox(
            sidebar, font=("Helvetica", 10), selectmode="single",
            bg="#F8FAFC", relief="flat", highlightthickness=1
        )
        self.peer_listbox.pack(fill="both", expand=True)
        self.peer_listbox.bind("<<ListboxSelect>>", self.on_peer_select)

        self.btn_handshake = tk.Button(
            sidebar, text="🔑 Initiate DH Key", bg="#0D9488", fg="white",
            font=("Helvetica", 8, "bold"), relief="flat", pady=4,
            command=self.initiate_handshake_with_selected
        )
        self.btn_handshake.pack(fill="x", pady=(5, 0))

        # Chat Transcript
        chat_frame = tk.LabelFrame(
            mid_frame, text=" 3. End-to-End Encrypted Message Feed ",
            bg="#FFFFFF", fg="#1E293B", font=("Helvetica", 9, "bold"),
            padx=8, pady=8
        )
        chat_frame.pack(side="right", fill="both", expand=True)

        self.chat_display = scrolledtext.ScrolledText(
            chat_frame, wrap="word", font=("Helvetica", 10),
            bg="#F8FAFC", relief="flat", state="disabled"
        )
        self.chat_display.pack(fill="both", expand=True)

        # Configure color tags
        self.chat_display.tag_config("sent", foreground="#1E40AF", font=("Helvetica", 10, "bold"))
        self.chat_display.tag_config("received", foreground="#047857", font=("Helvetica", 10, "bold"))
        self.chat_display.tag_config("system", foreground="#64748B", font=("Helvetica", 9, "italic"))
        self.chat_display.tag_config("alert", foreground="#DC2626", background="#FEE2E2", font=("Helvetica", 10, "bold"))
        self.chat_display.tag_config("verified", foreground="#059669", font=("Helvetica", 8, "bold"))

    def _build_input_and_demo_panel(self):
        bottom_frame = tk.Frame(self.root, bg="#FFFFFF", padx=12, pady=10)
        bottom_frame.pack(fill="x", padx=12, pady=(4, 10))

        # MITM Simulation Checkbox
        self.mitm_corrupt_var = tk.BooleanVar(value=False)
        self.chk_mitm = tk.Checkbutton(
            bottom_frame, text="⚠️ Simulate Active MITM Tamper Attack (Corrupt Ciphertext Before Sending)",
            variable=self.mitm_corrupt_var, bg="#FFFFFF", fg="#DC2626",
            font=("Helvetica", 9, "bold"), activebackground="#FFFFFF"
        )
        self.chk_mitm.pack(anchor="w", pady=(0, 6))

        # Input box + Send Button
        msg_box_frame = tk.Frame(bottom_frame, bg="#FFFFFF")
        msg_box_frame.pack(fill="x")

        self.msg_entry = tk.Entry(msg_box_frame, font=("Helvetica", 11), bg="#F8FAFC", relief="solid", bd=1)
        self.msg_entry.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 8))
        self.msg_entry.bind("<Return>", lambda event: self.send_message())

        self.btn_send = tk.Button(
            msg_box_frame, text="🔒 Encrypt & Send", bg="#2563EB", fg="white",
            font=("Helvetica", 10, "bold"), relief="flat", padx=16, pady=6,
            command=self.send_message
        )
        self.btn_send.pack(side="right")

    # ==========================================================================
    # LOGGING & HELPERS
    # ==========================================================================
    def log_message(self, tag, header, body="", peer=None):
        if self.is_destroyed:
            return
        now = datetime.datetime.now().strftime("%H:%M:%S")
        header_with_time = f"[{now}] {header}"

        target_peer = peer if peer is not None else self.active_peer
        if target_peer:
            if target_peer not in self.conversations:
                self.conversations[target_peer] = []
            self.conversations[target_peer].append((tag, header_with_time, body))
            if self.active_peer == target_peer:
                self.chat_display.configure(state="normal")
                self.chat_display.insert(tk.END, f"{header_with_time}\n", tag)
                if body:
                    self.chat_display.insert(tk.END, f"{body}\n\n")
                self.chat_display.see(tk.END)
                self.chat_display.configure(state="disabled")
        else:
            self.system_history.append((tag, header_with_time, body))
            self.chat_display.configure(state="normal")
            self.chat_display.insert(tk.END, f"{header_with_time}\n", tag)
            if body:
                self.chat_display.insert(tk.END, f"{body}\n\n")
            self.chat_display.see(tk.END)
            self.chat_display.configure(state="disabled")

    def _select_peer(self, peer):
        self.active_peer = peer
        self._refresh_chat_display()
        if peer not in self.peer_sessions:
            self.initiate_handshake(peer)
        else:
            self.status_label.configure(
                text=f"🔒 E2EE Active with '{peer}' (AES-256-CBC Session Key Ready)",
                fg="#059669"
            )

    def _refresh_chat_display(self):
        if self.is_destroyed:
            return
        self.chat_display.configure(state="normal")
        self.chat_display.delete("1.0", tk.END)
        if self.active_peer:
            messages = self.conversations.get(self.active_peer, [])
            if not messages:
                self.chat_display.insert(tk.END, f"[*] E2EE session opened with '{self.active_peer}'.\n[*] Send a message to exchange Diffie-Hellman keys and chat securely.\n\n", "system")
            else:
                for tag, header, body in messages:
                    self.chat_display.insert(tk.END, f"{header}\n", tag)
                    if body:
                        self.chat_display.insert(tk.END, f"{body}\n\n")
        else:
            if self.system_history:
                for tag, header, body in self.system_history:
                    self.chat_display.insert(tk.END, f"{header}\n", tag)
                    if body:
                        self.chat_display.insert(tk.END, f"{body}\n\n")
            else:
                self.chat_display.insert(tk.END, "[*] Select an online peer on the left to start an encrypted chat.\n", "system")
        self.chat_display.see(tk.END)
        self.chat_display.configure(state="disabled")

    def _send_raw_packet(self, packet_dict):
        """Sends packet with newline delimiter for byte-level TCP stream safety."""
        if not self.sock:
            return False
        try:
            data = (json.dumps(packet_dict) + "\n").encode('utf-8')
            self.sock.sendall(data)
            return True
        except Exception as e:
            self.log_message("alert", f"[ERROR] Failed to send over socket: {e}")
            return False

    # ==========================================================================
    # ASYNCHRONOUS NON-BLOCKING CONNECTION
    # ==========================================================================
    def toggle_connection(self):
        if not self.is_connected:
            self.connect_to_server()
        else:
            self.disconnect_from_server()

    def connect_to_server(self):
        if self.is_connecting:
            return

        ip = self.ip_entry.get().strip()
        port_str = self.port_entry.get().strip()
        user = self.user_entry.get().strip()

        if not ip or not port_str or not user:
            messagebox.showerror("Validation Error", "Please provide Server IP, Port, and Username.")
            return

        try:
            port = int(port_str)
        except ValueError:
            messagebox.showerror("Validation Error", "Port must be an integer.")
            return

        self.is_connecting = True
        self.btn_connect.configure(text="Connecting...", bg="#F59E0B", state="disabled")
        self.status_icon.configure(text="🟡")
        self.status_label.configure(text=f"Connecting to {ip}:{port}...", fg="#D97706")

        # Spawn non-blocking thread so GUI NEVER freezes
        threading.Thread(target=self._async_connect_worker, args=(ip, port, user), daemon=True).start()

    def _async_connect_worker(self, ip, port, user):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)  # 5-second connection timeout prevents infinite freeze
            sock.connect((ip, port))
            sock.settimeout(None) # Restore blocking mode for worker loop

            # Generate local Diffie-Hellman Keypair
            priv_dh, pub_dh = crypto_engine.generate_dh_keypair()

            # Send registration packet with newline
            reg_pkt = {"type": "register", "username": user}
            reg_bytes = (json.dumps(reg_pkt) + "\n").encode('utf-8')
            sock.sendall(reg_bytes)

            self.safe_after(0, self._on_connect_success, sock, user, priv_dh, pub_dh, ip, port)
        except Exception as e:
            self.safe_after(0, self._on_connect_failed, str(e), ip, port)

    def _on_connect_success(self, sock, user, priv_dh, pub_dh, ip, port):
        if self.is_destroyed:
            try: sock.close()
            except Exception: pass
            return

        self.sock = sock
        self.username = user
        self.my_private_dh = priv_dh
        self.my_public_dh = pub_dh
        self.is_connected = True
        self.is_connecting = False

        self.btn_connect.configure(text="Disconnect", bg="#DC2626", state="normal")
        self.status_icon.configure(text="🟢")
        self.status_label.configure(
            text=f"Connected as '{self.username}' | Diffie-Hellman 2048 Ready",
            fg="#059669"
        )
        self.log_message("system", f"[*] Connected to Server {ip}:{port} as '{self.username}'.")
        self.log_message("system", f"[*] DH-2048 Private Exponent and Public Key generated locally.")

        # Start background receiver thread
        threading.Thread(target=self._listen_server, daemon=True).start()

    def _on_connect_failed(self, error_msg, ip, port):
        if self.is_destroyed:
            return
        self.is_connected = False
        self.is_connecting = False
        self.btn_connect.configure(text="Connect", bg="#1E40AF", state="normal")
        self.status_icon.configure(text="🔴")
        self.status_label.configure(text=f"Connection failed to {ip}:{port}.", fg="#DC2626")
        messagebox.showerror(
            "Connection Failed",
            f"Could not connect to {ip}:{port}.\n\nEnsure that 'python3 server.py' is running on the host laptop first!\n\nDetails: {error_msg}"
        )

    def disconnect_from_server(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self.sock = None
        self.is_connected = False
        self.is_connecting = False
        if not self.is_destroyed:
            self.btn_connect.configure(text="Connect", bg="#1E40AF", state="normal")
            self.status_icon.configure(text="⚪")
            self.status_label.configure(text="Status: Disconnected.", fg="#475569")
            self.peer_listbox.delete(0, tk.END)
            self.peer_sessions.clear()
            self.pending_outbox.clear()
            self.pending_handshakes.clear()
            self.unread_peers.clear()
            self.last_user_list.clear()
            self.conversations.clear()
            self.system_history.clear()
            self.active_peer = None
            self.log_message("system", "[*] Disconnected from relay server.")
            self._refresh_chat_display()

    # ==========================================================================
    # RECEIVER LOOP WITH BYTE-LEVEL TCP LINE FRAMING
    # ==========================================================================
    def _listen_server(self):
        buffer = bytearray()
        while self.is_connected and self.sock:
            try:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                buffer.extend(chunk)

                if len(buffer) > MAX_FRAME_SIZE:
                    break

                while b"\n" in buffer:
                    line, _, remaining = buffer.partition(b"\n")
                    buffer = bytearray(remaining)
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        packet = json.loads(line.decode('utf-8'))
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        continue

                    pkt_type = packet.get("type")

                    if pkt_type == "user_list":
                        users = packet.get("users", [])
                        self.safe_after(0, self._update_user_list, users)

                    elif pkt_type == "key_exchange":
                        sender = packet.get("from")
                        raw_pub = packet.get("public_key")
                        if sender and raw_pub and str(raw_pub).isdigit():
                            peer_pub = int(raw_pub)
                            is_reply = packet.get("is_reply", False)
                            self.safe_after(0, self._handle_incoming_key_exchange, sender, peer_pub, is_reply)

                    elif pkt_type == "message":
                        self.safe_after(0, self._handle_incoming_message, packet)

                    elif pkt_type == "error":
                        err_msg = packet.get("message", "Unknown error")
                        self.safe_after(0, self.log_message, "alert", f"[SERVER ERROR] {err_msg}")

            except Exception:
                break

        if self.is_connected and not self.is_destroyed:
            self.safe_after(0, self.disconnect_from_server)

    def _update_user_list(self, users):
        self.last_user_list = list(users)
        current_active = self.active_peer

        online_peers = [u for u in users if u != self.username]
        if current_active and current_active not in online_peers:
            self.status_label.configure(
                text=f"⚠️ Peer '{current_active}' disconnected from server.",
                fg="#D97706"
            )

        self.peer_listbox.delete(0, tk.END)
        for u in online_peers:
            display_name = f"{u} (*)" if u in self.unread_peers else u
            self.peer_listbox.insert(tk.END, display_name)

        if current_active:
            for i in range(self.peer_listbox.size()):
                item_text = self.peer_listbox.get(i).replace(" (*)", "").strip()
                if item_text == current_active:
                    self.peer_listbox.selection_set(i)
                    break

    def on_peer_select(self, event=None):
        if not self.peer_listbox.curselection():
            return
        raw_name = self.peer_listbox.get(self.peer_listbox.curselection())
        selected_peer = raw_name.replace(" (*)", "").strip()
        self.unread_peers.discard(selected_peer)
        self._select_peer(selected_peer)
        self._update_user_list(self.last_user_list)

    def initiate_handshake_with_selected(self):
        target = self.active_peer
        if not target and self.peer_listbox.curselection():
            target = self.peer_listbox.get(self.peer_listbox.curselection())
        if not target:
            messagebox.showinfo("Select Peer", "Please select a peer from the online list first.")
            return
        self._select_peer(target)
        self.initiate_handshake(target)

    def initiate_handshake(self, peer_username):
        if not self.is_connected or not self.sock:
            return

        # Debouncing: Prevent redundant public key floods
        if peer_username in self.pending_handshakes:
            return
        self.pending_handshakes.add(peer_username)

        pkt = {
            "type": "key_exchange",
            "from": self.username,
            "to": peer_username,
            "public_key": str(self.my_public_dh),
            "is_reply": False
        }
        self._send_raw_packet(pkt)
        self.log_message("system", f"[*] Sent Diffie-Hellman Public Key to '{peer_username}'. Negotiating shared key...", peer=peer_username)

    def _handle_incoming_key_exchange(self, sender, peer_pub, is_reply):
        # Remove from pending debouncing set
        self.pending_handshakes.discard(sender)

        # Derive 256-bit AES session key using SHA-256 KDF
        try:
            session_key = crypto_engine.compute_shared_session_key(peer_pub, self.my_private_dh)
            self.peer_sessions[sender] = session_key
        except ValueError as e:
            self.log_message("alert", f"🚨 [KEY EXCHANGE FAILED] Malicious or invalid key from '{sender}': {e}", peer=sender)
            return

        self.log_message(
            "verified",
            f"🔑 [DH KEY AGREEMENT COMPLETE] Synchronized 256-bit AES Session Key with '{sender}'!",
            f"Derived Key Fingerprint: {session_key[:8].hex()}... (Cipher: AES-256-CBC + HMAC-SHA256)",
            peer=sender
        )

        if self.active_peer == sender:
            self.status_label.configure(
                text=f"🔒 E2EE Active with '{sender}' (AES-256-CBC + HMAC-SHA256)",
                fg="#059669"
            )

        # If this wasn't a reply, send our public key back
        if not is_reply:
            reply_pkt = {
                "type": "key_exchange",
                "from": self.username,
                "to": sender,
                "public_key": str(self.my_public_dh),
                "is_reply": True
            }
            self._send_raw_packet(reply_pkt)
            self.log_message("system", f"[*] Returned DH Public Key to '{sender}'. Both parties are now E2EE secure.", peer=sender)

        # Flush any messages queued for this peer during key exchange
        if sender in self.pending_outbox and self.pending_outbox[sender]:
            queued_list = self.pending_outbox.pop(sender)
            self.log_message("system", f"[*] Flushing {len(queued_list)} queued message(s) to '{sender}'...", peer=sender)
            for queued_msg in queued_list:
                self._encrypt_and_transmit(sender, queued_msg)

    # ==========================================================================
    # MESSAGE TRANSMISSION & INTEGRITY DEMO
    # ==========================================================================
    def send_message(self):
        if not self.is_connected:
            messagebox.showwarning("Not Connected", "Please connect to the server first.")
            return

        recipient = self.active_peer
        if not recipient and self.peer_listbox.curselection():
            recipient = self.peer_listbox.get(self.peer_listbox.curselection())
            self._select_peer(recipient)

        if not recipient:
            messagebox.showwarning("Select Recipient", "Please select a recipient from the 'Peers Online' list.")
            return

        plaintext = self.msg_entry.get().strip()
        if not plaintext:
            return

        self.msg_entry.delete(0, tk.END)

        session_key = self.peer_sessions.get(recipient)
        if not session_key:
            # Auto-queue message and start handshake seamlessly
            if recipient not in self.pending_outbox:
                self.pending_outbox[recipient] = []
            self.pending_outbox[recipient].append(plaintext)
            self.log_message("system", f"[*] Key exchange pending with '{recipient}'. Queued message to auto-send.", peer=recipient)
            self.initiate_handshake(recipient)
            return

        self._encrypt_and_transmit(recipient, plaintext)

    def _encrypt_and_transmit(self, recipient, plaintext):
        session_key = self.peer_sessions.get(recipient)
        if not session_key:
            return

        # 1. Encrypt message locally with AES-256-CBC and generate HMAC-SHA256 seal
        encrypted_dict = crypto_engine.encrypt_message(session_key, plaintext)

        # 2. MITM Tamper Simulation check
        is_tampered = self.mitm_corrupt_var.get()
        if is_tampered:
            ct = list(encrypted_dict["ciphertext"])
            # Flip the first hexadecimal character (active bit flip)
            ct[0] = '0' if ct[0] != '0' else '1'
            encrypted_dict["ciphertext"] = "".join(ct)

        # 3. Construct transmission packet
        pkt = {
            "type": "message",
            "from": self.username,
            "to": recipient,
            "iv": encrypted_dict["iv"],
            "ciphertext": encrypted_dict["ciphertext"],
            "hmac_tag": encrypted_dict["hmac_tag"],
            "timestamp": time.time()
        }

        # 4. Transmit packet over socket to blind server relay
        if self._send_raw_packet(pkt):
            if is_tampered:
                self.mitm_corrupt_var.set(False)
                self.log_message(
                    "alert",
                    f"⚠️ [TAMPER ATTACK SIMULATED] Sent intentionally corrupted ciphertext to '{recipient}'!\n(MITM checkbox auto-reset to OFF)",
                    f"Corrupted Ciphertext Preview: {pkt['ciphertext'][:24]}...",
                    peer=recipient
                )
            else:
                self.log_message(
                    "sent",
                    f"You -> {recipient}:",
                    f"{plaintext}\n(AES-256-CBC Encrypted & HMAC-SHA256 Signed)",
                    peer=recipient
                )

    def _handle_incoming_message(self, packet):
        sender = packet.get("from")
        session_key = self.peer_sessions.get(sender)

        if not session_key:
            self.log_message("alert", f"⚠️ [ERROR] Received message from '{sender}', but no shared DH session key exists!", peer=sender)
            return

        # Attempt decryption and HMAC verification
        try:
            plaintext = crypto_engine.decrypt_message(session_key, packet)
            self.log_message(
                "received",
                f"{sender}:",
                f"{plaintext}\n[🛡️ HMAC: VERIFIED AUTHENTIC]",
                peer=sender
            )
            if sender and sender != self.active_peer:
                self.unread_peers.add(sender)
                self._update_user_list(self.last_user_list)
                self.status_label.configure(
                    text=f"💬 New message from '{sender}'! (Click peer in list to view)",
                    fg="#2563EB"
                )
        except ValueError as e:
            # Tampering was detected!
            self.log_message(
                "alert",
                f"🚨 SECURITY ALERT: MESSAGE TAMPERING DETECTED FROM '{sender}'!",
                f"Details: {e}\nAction: Packet was discarded. Plaintext was protected from alteration.",
                peer=sender
            )
            messagebox.showwarning(
                "Security Alert: Message Tampered",
                f"A message from '{sender}' failed cryptographic integrity verification!\n\nThe packet was altered in transit and has been dropped."
            )

    def on_close(self):
        self.is_destroyed = True
        self.disconnect_from_server()
        try:
            self.root.destroy()
        except Exception:
            pass


def main():
    root = tk.Tk()
    app = SecureChatClientGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
