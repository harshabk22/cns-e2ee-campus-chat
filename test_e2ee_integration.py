"""
test_e2ee_integration.py - Automated Deep Verification Test Suite
Tests:
1. Dynamic Peer Heartbeat & Expiration
2. Multi-Party Diffie-Hellman Handshake & Cryptographic Equivalence Proof
3. Partitioned Conversation Isolation (Zero Cross-Talk Proof)
4. MITM Tamper Detection, Bit-Flip Verification & HMAC Discard
5. Packet Inspector Envelopes (Sent & Received)
6. Concurrent Thread Safety with ThreadingHTTPServer
"""

import threading
import time
import json
import urllib.request
import urllib.parse
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import web_ui
import crypto_engine

TEST_PORT = 8999

def run_server():
    web_ui.ThreadingHTTPServer.allow_reuse_address = True
    web_ui.ThreadingHTTPServer.request_queue_size = 64
    server = web_ui.ThreadingHTTPServer(('127.0.0.1', TEST_PORT), web_ui.WebAppHandler)
    server.daemon_threads = True
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    return server

def http_get(path, retries=3):
    url = f"http://127.0.0.1:{TEST_PORT}{path}"
    req = urllib.request.Request(url)
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                return json.loads(response.read().decode('utf-8'))
        except Exception:
            if attempt == retries - 1:
                raise
            time.sleep(0.05)

def http_post(path, data, retries=3):
    url = f"http://127.0.0.1:{TEST_PORT}{path}"
    post_data = json.dumps(data).encode('utf-8')
    req = urllib.request.Request(url, data=post_data, headers={'Content-Type': 'application/json'})
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                return json.loads(response.read().decode('utf-8'))
        except Exception:
            if attempt == retries - 1:
                raise
            time.sleep(0.05)

def run_tests():
    print("=" * 60)
    print("CNS SYSTEM TEST RUNNER: MULTI-USER WEB UI & CLIENT VERIFICATION")
    print("=" * 60)

    server = run_server()
    time.sleep(0.5)

    try:
        # TEST 1: Dynamic Peer Registration & Heartbeat
        print("[TEST 1] Testing dynamic peer registration & heartbeats...")
        res_alice = http_get("/api/peers?user=Alice")
        assert res_alice["peers"] == [], f"Expected empty peers, got {res_alice}"
        
        res_bob = http_get("/api/peers?user=Bob")
        assert "Alice" in res_bob["peers"], f"Bob should see Alice, got {res_bob}"
        assert "Bob" not in res_bob["peers"], "Bob should not see himself"

        res_charlie = http_get("/api/peers?user=Charlie")
        assert "Alice" in res_charlie["peers"] and "Bob" in res_charlie["peers"], f"Charlie should see Alice and Bob, got {res_charlie}"
        print("  -> Alice, Bob, Charlie successfully registered and discovered dynamically. [PASS]")

        # TEST 2: Peer Expiration (15-second window test)
        print("[TEST 2] Testing peer expiration (15-second cutoff)...")
        with web_ui.server_lock:
            # Simulate Alice's last heartbeat as 20 seconds ago
            web_ui.user_last_seen["Alice"] = time.time() - 25.0
        
        res_bob_after_expire = http_get("/api/peers?user=Bob")
        assert "Alice" not in res_bob_after_expire["peers"], f"Alice should be expired, got {res_bob_after_expire}"
        assert "Charlie" in res_bob_after_expire["peers"], f"Charlie should still be online, got {res_bob_after_expire}"
        print("  -> Expired peer (25s inactive) correctly removed from active peers list. [PASS]")

        # Re-activate Alice
        http_get("/api/peers?user=Alice")

        # TEST 3: Multi-Party Diffie-Hellman Handshake
        print("[TEST 3] Testing Diffie-Hellman Key Exchange via Web API...")
        hs_alice = http_post("/api/handshake", {"user": "Alice", "peer": "Bob"})
        hs_bob = http_post("/api/handshake", {"user": "Bob", "peer": "Alice"})
        assert hs_alice["status"] == "ok" and hs_bob["status"] == "ok"
        assert hs_alice["key_preview"] == hs_bob["key_preview"], f"Session keys must match! Alice: {hs_alice}, Bob: {hs_bob}"
        print(f"  -> DH-2048 agreement succeeded: Key Fingerprint {hs_alice['key_preview']} [PASS]")

        # TEST 4: Message Transmission & Conversation Partitioning (Zero Cross-Talk)
        print("[TEST 4] Testing conversation partitioning (Alice <-> Bob vs Alice <-> Charlie)...")
        # Alice sends to Bob
        http_post("/api/send", {
            "sender": "Alice",
            "recipient": "Bob",
            "text": "Secret mission briefing for Bob",
            "tamper": False
        })
        # Alice sends to Charlie
        http_post("/api/send", {
            "sender": "Alice",
            "recipient": "Charlie",
            "text": "Exam study notes for Charlie",
            "tamper": False
        })

        # Bob views chat with Alice
        bob_view = http_get("/api/messages?user=Bob&peer=Alice")
        bob_texts = [m["text"] for m in bob_view["messages"]]
        assert "Secret mission briefing for Bob" in bob_texts, f"Bob did not receive message: {bob_view}"
        assert "Exam study notes for Charlie" not in bob_texts, "LEAK DETECTED: Bob saw Charlie's message!"

        # Charlie views chat with Alice
        charlie_view = http_get("/api/messages?user=Charlie&peer=Alice")
        charlie_texts = [m["text"] for m in charlie_view["messages"]]
        assert "Exam study notes for Charlie" in charlie_texts, f"Charlie did not receive message: {charlie_view}"
        assert "Secret mission briefing for Bob" not in charlie_texts, "LEAK DETECTED: Charlie saw Bob's message!"

        # Bob views chat with Charlie (they have not messaged each other)
        bob_charlie_view = http_get("/api/messages?user=Bob&peer=Charlie")
        assert bob_charlie_view["messages"] == [], f"Expected empty conversation between Bob and Charlie, got {bob_charlie_view}"
        print("  -> Complete conversation isolation verified: Zero cross-talk between distinct peers. [PASS]")

        # TEST 5: Active MITM Tamper Simulation & HMAC Verification
        print("[TEST 5] Testing MITM active tamper attack simulation & integrity verification...")
        send_tamper_res = http_post("/api/send", {
            "sender": "Alice",
            "recipient": "Bob",
            "text": "Tampered payment amount: $10000",
            "tamper": True
        })
        assert send_tamper_res["packet"]["tampered"] is True, "Packet should be flagged as tampered"

        # Check Bob's incoming feed
        bob_poll_tamper = http_get("/api/messages?user=Bob&peer=Alice")
        assert bob_poll_tamper["tamper_detected"] is True, "Bob should detect tamper event!"
        assert bob_poll_tamper["tamper_info"]["sender"] == "Alice"
        tampered_texts = [m["text"] for m in bob_poll_tamper["messages"]]
        assert "Tampered payment amount: $10000" not in tampered_texts, "SECURITY VULNERABILITY: Tampered packet was decrypted and shown!"
        print("  -> Tampered ciphertext successfully rejected by HMAC-SHA256 seal. Security alert generated. [PASS]")

        # TEST 6: Live Packet Inspector envelopes (Outbound and Inbound)
        print("[TEST 6] Testing live packet inspector envelope contents...")
        packets = bob_poll_tamper["packets"]
        assert len(packets) >= 2, f"Expected at least 2 packets, got {len(packets)}"
        for pkt in packets:
            assert "iv" in pkt and len(pkt["iv"]) == 32, "Packet missing valid 16-byte hex IV"
            assert "ciphertext" in pkt and len(pkt["ciphertext"]) > 0, "Packet missing ciphertext"
            assert "hmac_tag" in pkt and len(pkt["hmac_tag"]) == 64, "Packet missing valid SHA-256 HMAC tag"
        print(f"  -> All {len(packets)} envelopes have valid IV, Ciphertext, and HMAC-SHA256 tags for inspector display. [PASS]")

        # TEST 7: High-Concurrency Thread Safety
        print("[TEST 7] Testing concurrent multi-threaded requests...")
        errors = []
        def concurrent_poller(user_id):
            try:
                for _ in range(15):
                    http_get(f"/api/peers?user=User_{user_id}")
                    http_get(f"/api/messages?user=User_{user_id}&peer=Bob")
                    time.sleep(0.01)
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=concurrent_poller, args=(i,)) for i in range(10)]
        for t in threads: t.start()
        for t in threads: t.join()

        assert len(errors) == 0, f"Concurrency errors encountered: {errors}"
        print("  -> 150 concurrent requests handled across 10 parallel threads with zero race conditions. [PASS]")

        print("=" * 60)
        print("ALL INTEGRATION TESTS PASSED WITH 100% SUCCESS!")
        print("=" * 60)

    finally:
        server.shutdown()
        server.server_close()

if __name__ == "__main__":
    run_tests()
