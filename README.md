# 🔒 cns-e2ee-campus-chat
> **End-to-End Encrypted (E2EE) Secure Chat Application for Campus Wi-Fi**  
> *Course: Cryptography and Network Security (CNS - E1CSA311)*

---

## 👥 Student Team

| Name | USN | Contribution Role |
| :--- | :--- | :--- |
| **Harshavardhan BK** | 1MS23CS079 | Cryptographic Engine (DH-2048, AES-256-CBC, HMAC-SHA256, Testing) |
| **Ullas S Revanaki** | 1MS23CS233 | Desktop Client GUI (Tkinter), Key Exchange Handshake, MITM Demo |
| **Gajavardhan reddy** | 1MS23CS069 | Zero-Knowledge Blind Socket Relay Server, TCP Framing & Network Routing |

---

## 🛡️ Security Architecture & Algorithms

1. **Key Agreement:** Diffie-Hellman Key Exchange (RFC 3526 2048-bit MODP Group 14) with safe-prime subgroup validation.
2. **Key Derivation:** SHA-256 KDF with NIST SP 800-108 domain-separated subkeys (`k_enc` for encryption, `k_mac` for authentication).
3. **Payload Confidentiality:** AES-256 in CBC mode with PKCS#7 padding.
4. **Integrity & Tamper Detection:** HMAC-SHA256 (Encrypt-then-MAC) with constant-time verification.
5. **Zero-Knowledge Relay Server:** Relays encrypted envelopes without holding private keys, shared secrets, or decrypting message payloads.
6. **Robust TCP Framing:** Byte-level newline-delimited JSON (`b"\n"`) stream handling.

---

## 📁 Repository Structure

```text
├── crypto_engine.py             # Core Cryptographic Library (DH, AES-256, HMAC, UT-01 to UT-05)
├── server.py                    # Multi-threaded Blind Socket Relay Server
├── client.py                    # Tkinter Desktop Chat GUI with MITM Attack Simulation
├── Micro project Template-CNS.docx # Formal Project Proposal Document
├── Review_2_and_3_Contents.md   # Complete Review 2 & 3 Deliverables & Test Evidence
├── cns_flowchart.png            # End-to-End Cryptographic Sequence Flowchart
├── cns_mindmap.png              # System Architecture Mindmap
└── README.md                    # Project Documentation
```

---

## 🚀 Quick Start Guide

### Step 1: Run the Cryptographic Unit Test Suite (UT-01 to UT-05)
```bash
python3 crypto_engine.py
```
*Validates key generation, session key equivalence, AES encryption/decryption, and 1-bit tamper rejection.*

### Step 2: Start the Relay Server (Host Laptop / Gajavardhan)
```bash
python3 server.py
```
*Listens on port `5555` and displays the local Wi-Fi IP address (e.g., `192.168.x.x`).*

### Step 3: Launch Clients (Alice / Harsha & Bob / Ullas)
In two separate terminals:
```bash
python3 client.py
```
- Enter Server IP (`127.0.0.1` for local testing or the Host Wi-Fi IP for multi-laptop demo).
- Port: `5555`.
- Username: `Harsha` / `Ullas`.
- Click **Connect**.

---

## ⚠️ Live MITM Tamper Attack Demo
1. Connect both clients and select a peer from the **Peers Online** list.
2. Check the box: `⚠️ Simulate Active MITM Tamper Attack (Corrupt Ciphertext Before Sending)`.
3. Type and send a message.
4. The receiver's client immediately rejects the message with:
   `🚨 SECURITY ALERT: MESSAGE TAMPERING DETECTED!`.
   The packet is discarded, demonstrating real-time HMAC-SHA256 integrity protection.
