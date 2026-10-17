# 🔒 E2EE Campus Wi-Fi Chat
> A lightweight, zero-knowledge private desktop chat app built for our college Cryptography & Network Security (CNS) micro-project.

---

### 💡 Why We Built This
College hostel and campus Wi-Fi networks are shared by hundreds of students. If you chat over plain HTTP or unencrypted sockets, anyone with Wireshark can read your messages in plain text.

We built this app so two students on the same campus Wi-Fi can chat with **total privacy**. Even the student hosting the relay server **cannot read or tamper with any message**.

---

### 🧠 How It Works (In Plain English)

```text
Harsha's Laptop                 Host Relay Server                 Ullas's Laptop
     [ Alice ]                      [ Host ]                         [ Bob ]
         │                              │                               │
         │──── 1. Diffie-Hellman Key Exchange (Public Keys only) ──────>│
         │<─── 2. Negotiates Shared 256-bit AES Key in Secret ──────────│
         │                              │                               │
         │==== 3. AES-256 Encrypted Message + HMAC-SHA256 Seal ========>│
         │          (Server only sees scrambled ciphertext hex)         │
         │                              │                               │
```

1. **Secret Key Agreement:** When you click a classmate's name, both laptops agree on a temporary 256-bit AES key using **Diffie-Hellman (2048-bit)**. The secret key never travels across the network.
2. **Ironclad Encryption:** Every message is locked with **AES-256 in CBC mode** before it ever leaves your machine.
3. **Tamper Proof (HMAC):** An **HMAC-SHA256 seal** is stamped on each packet. If anyone on the Wi-Fi alters even 1 bit in transit, the message is instantly rejected.
4. **Blind Relay:** The server simply forwards encrypted packets. It has zero keys and zero ability to decrypt.

---

### 👥 The Team

| Name | USN | What We Built |
| :--- | :--- | :--- |
| **Harshavardhan BK** | 1MS23CS079 | Cryptographic Engine (DH, AES, HMAC, and self-testing) |
| **Ullas S Revanaki** | 1MS23CS233 | Desktop Client GUI & Live MITM Tamper Simulator |
| **Gajavardhan reddy** | 1MS23CS069 | Zero-Knowledge Blind Socket Relay Server & TCP Framing |

---

### 🚀 How to Run It (3 Easy Steps)

No complicated installs or Docker needed! Just plain Python 3:

#### 1. Test the Crypto Engine First
Verify that all algorithms and tamper protections pass:
```bash
python3 crypto_engine.py
```
*(You should see `ALL CRYPTOGRAPHIC TESTS PASSED WITH 100% SUCCESS!`)*

#### 2. Start the Server (Host Laptop / Gajavardhan)
```bash
python3 server.py
```
*(The terminal will show your local Wi-Fi IP address, like `192.168.1.45`)*

#### 3. Start the Chat Windows (Harsha & Ullas)
Open two terminal windows (or run on two different laptops on the same Wi-Fi):
```bash
python3 client.py
```
- **Server IP:** `127.0.0.1` *(if testing on 1 laptop)* or the host's Wi-Fi IP.
- **Port:** `5555`
- **Username:** Type your name and hit **Connect**!

---

### 🎯 Best Feature to Demo to Your Teacher (Live Hack Simulation)

We built an intentional **MITM (Man-In-The-Middle) Tamper Toggle** right into the app to demonstrate integrity protection:

1. Check the box:  
   `⚠️ Simulate Active MITM Tamper Attack (Corrupt Ciphertext Before Sending)`
2. Send a message like *"Let's meet at 5 PM"*.
3. The app intentionally flips a bit in the encrypted data before sending.
4. On the receiver's screen, an instant alert pops up:  
   `🚨 SECURITY ALERT: MESSAGE TAMPERING DETECTED!`
5. The corrupted packet is dropped immediately, proving that HMAC-SHA256 successfully caught the attack!
