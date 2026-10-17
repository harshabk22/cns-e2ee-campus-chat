"""
test_edge_cases.py - Deep Verification of Edge Cases & Hardening
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

TEST_PORT = 9123

def run_server():
    web_ui.ThreadingHTTPServer.allow_reuse_address = True
    web_ui.ThreadingHTTPServer.request_queue_size = 64
    server = web_ui.ThreadingHTTPServer(('127.0.0.1', TEST_PORT), web_ui.WebAppHandler)
    server.daemon_threads = True
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    return server

def http_get(path):
    url = f"http://127.0.0.1:{TEST_PORT}{path}"
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=5) as response:
        return json.loads(response.read().decode('utf-8'))

def http_post(path, data):
    url = f"http://127.0.0.1:{TEST_PORT}{path}"
    post_data = json.dumps(data).encode('utf-8')
    req = urllib.request.Request(url, data=post_data, headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return json.loads(response.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode('utf-8'))

def main():
    print("=" * 60)
    print("CNS EDGE CASE VERIFICATION SUITE")
    print("=" * 60)
    server = run_server()
    time.sleep(0.3)

    try:
        # 1. Immediate Leave API test
        print("[EC-01] Testing immediate peer departure via /api/leave...")
        http_get("/api/peers?user=UserLeaveTest")
        peers_before = http_get("/api/peers?user=Observer")["peers"]
        assert "UserLeaveTest" in peers_before, "UserLeaveTest should be present"

        # User leaves immediately
        res_leave = http_post("/api/leave", {"user": "UserLeaveTest"})
        assert res_leave["status"] == "left"

        peers_after = http_get("/api/peers?user=Observer")["peers"]
        assert "UserLeaveTest" not in peers_after, "UserLeaveTest should be instantly pruned without 15s wait"
        print("  -> Instant peer pruning on departure verified. [PASS]")

        # 2. Peer name with apostrophe / quotes / unicode
        print("[EC-02] Testing peer names with apostrophes and unicode...")
        complex_name = "O'Connor 😊"
        encoded = urllib.parse.quote(complex_name)
        http_get(f"/api/peers?user={encoded}")
        peers = http_get("/api/peers?user=Observer")["peers"]
        assert complex_name in peers, f"Expected {complex_name} in peers, got {peers}"

        # Handshake with complex name
        hs = http_post("/api/handshake", {"user": complex_name, "peer": "Observer"})
        assert hs["status"] == "ok"
        print("  -> Complex peer names with apostrophes & unicode supported. [PASS]")

        # 3. Unicode and emoji encrypted messaging
        print("[EC-03] Testing encrypted messaging with Unicode, emojis, newlines & code snippets...")
        unicode_msg = "Hello! 🚀 🔒 सुरक्षित संदेश \nLine 2: <html>alert('test')</html>"
        send_res = http_post("/api/send", {
            "sender": "Observer",
            "recipient": complex_name,
            "text": unicode_msg,
            "tamper": False
        })
        assert send_res["status"] == "sent"

        msgs = http_get(f"/api/messages?user={encoded}&peer=Observer")["messages"]
        assert any(m["text"] == unicode_msg for m in msgs), "Unicode message did not match plaintext!"
        print("  -> Multi-byte Unicode payload encrypted and recovered losslessly. [PASS]")

        # 4. Tamper notification in chat transcript for both sender and recipient
        print("[EC-04] Testing tamper notice presence in transcript...")
        send_tamper = http_post("/api/send", {
            "sender": "Observer",
            "recipient": complex_name,
            "text": "Tampered payment",
            "tamper": True
        })
        assert send_tamper["packet"]["tampered"] is True

        # Sender transcript
        sender_msgs = http_get(f"/api/messages?user=Observer&peer={encoded}")["messages"]
        tamper_sender_notices = [m for m in sender_msgs if m.get("tampered")]
        assert len(tamper_sender_notices) > 0, "Sender should see tamper notice in transcript!"
        assert "⚠️ [Tamper Simulation]" in tamper_sender_notices[0]["text"]

        # Recipient transcript
        recip_msgs = http_get(f"/api/messages?user={encoded}&peer=Observer")["messages"]
        tamper_recip_notices = [m for m in recip_msgs if m.get("tampered")]
        assert len(tamper_recip_notices) > 0, "Recipient should see tamper alert in transcript!"
        assert "🚨 [Security Alert]" in tamper_recip_notices[0]["text"]
        print("  -> Tamper simulation transparently documented in transcripts for both parties. [PASS]")

        # 5. Invalid parameters robustness
        print("[EC-05] Testing boundary handling on empty / missing parameters...")
        empty_send = http_post("/api/send", {"sender": "", "recipient": ""})
        assert "error" in empty_send, "Expected 400 error for empty send"
        empty_hs = http_post("/api/handshake", {"user": "", "peer": ""})
        assert "error" in empty_hs, "Expected 400 error for empty handshake"
        empty_msgs = http_get("/api/messages?user=&peer=")
        assert empty_msgs["messages"] == [] and empty_msgs["tamper_detected"] is False
        print("  -> Boundary validation and error handling verified. [PASS]")

        print("=" * 60)
        print("ALL EDGE CASE TESTS PASSED WITH 100% SUCCESS!")
        print("=" * 60)
    finally:
        server.shutdown()
        server.server_close()

if __name__ == "__main__":
    main()
