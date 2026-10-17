# 🔒 E2EE Campus Wi-Fi Chat
> A lightweight, zero-knowledge private desktop chat app built for Cryptography & Network Security (CNS).

---

### 💡 Why This Was Built
Hostel and campus Wi-Fi networks are shared by hundreds of users. If you chat over plain HTTP or unencrypted sockets, anyone with packet sniffers (like Wireshark) can read your messages in plain text.

This application allows peers on the same local Wi-Fi to chat with **total privacy**. Even the machine hosting the relay server **cannot read or tamper with any message**.

---

### 🧠 How It Works (In Plain English)

```text
Client A (Alice)                Host Relay Server                 Client B (Bob)
     [ Alice ]                      [ Host ]                         [ Bob ]
         │                              │                               │
         │──── 1. Diffie-Hellman Key Exchange (Public Keys only) ──────>│
         │<─── 2. Negotiates Shared 256-bit AES Key in Secret ──────────│
         │                              │                               │
         │==== 3. AES-256 Encrypted Message + HMAC-SHA256 Seal ========>│
         │          (Server only sees scrambled ciphertext hex)         │
         │                              │                               │
```

1. **Secret Key Agreement:** When you connect with a peer, both machines agree on a temporary 256-bit AES key using **Diffie-Hellman (2048-bit)**. The secret key never travels across the network.
2. **Ironclad Encryption:** Every message is locked with **AES-256 in CBC mode** before it ever leaves your machine.
3. **Tamper Proof (HMAC):** An **HMAC-SHA256 seal** is stamped on each packet. If anyone on the network alters even 1 bit in transit, the message is instantly rejected.
4. **Blind Relay:** The server simply forwards encrypted packets. It has zero keys and zero ability to decrypt.

---

### 🚀 How to Run It (3 Easy Steps)

No complicated installs or Docker needed! Just plain Python 3:

#### 1. Test the Crypto Engine First
Verify that all algorithms and tamper protections pass:
```bash
python3 crypto_engine.py
```
*(You should see `ALL CRYPTOGRAPHIC TESTS PASSED WITH 100% SUCCESS!`)*

#### 2. Start the Server (Host Machine)
```bash
python3 server.py
```
*(The terminal will show your local Wi-Fi IP address, like `192.168.1.45`)*

#### 3. Start the Chat Windows (Desktop Client)
Open terminal windows (or run on two different laptops on the same Wi-Fi):
```bash
python3 client.py
```
- **Server IP:** `127.0.0.1` *(if testing on 1 laptop)* or the host's Wi-Fi IP.
- **Port:** `5555`
- **Username:** Automatically defaults to your system username (e.g., `Harsha`), or enter any custom name and hit **Connect**!

#### 4. Or Run the Multi-User Web UI (No Installs Required)
For a modern browser experience accessible across campus devices, phones, or laptops:
```bash
python3 web_ui.py
```
- Open `http://localhost:8080` in your browser (or on Wi-Fi: `http://<Wi-Fi IP>:8080`).
- Enter your display name or roll number on the onboarding modal.
- Active peers on the local network automatically appear via the 15-second heartbeat registry.
- Click any peer to initiate Diffie-Hellman 2048-bit key exchange and chat privately with partitioned message storage and real-time live packet inspection!

---

### 🎯 Best Feature to Demo (Live Hack Simulation)

An intentional **MITM (Man-In-The-Middle) Tamper Toggle** is built right into the app to demonstrate integrity protection:

1. Check the box:  
   `⚠️ Simulate Active MITM Tamper Attack (Corrupt Ciphertext Before Sending)`
2. Send a message like *"Let's meet at 5 PM"*.
3. The app intentionally flips a bit in the encrypted data before sending.
4. On the receiver's screen, an instant alert pops up:  
   `🚨 SECURITY ALERT: MESSAGE TAMPERING DETECTED!`
5. The corrupted packet is dropped immediately, proving that HMAC-SHA256 successfully caught the attack!
