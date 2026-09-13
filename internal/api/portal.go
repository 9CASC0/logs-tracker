package api

import (
	"net/http"
)

const portalHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Global Audit Logger — Public Verification Portal</title>
  <style>
    :root {
      --bg: #0d1117;
      --card-bg: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --text-muted: #8b949e;
      --accent: #58a6ff;
      --success: #3fb950;
      --danger: #f85149;
      --warning: #d29922;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      margin: 0;
      padding: 24px;
      line-height: 1.5;
    }
    .container {
      max-width: 900px;
      margin: 0 auto;
    }
    header {
      border-bottom: 1px solid var(--border);
      padding-bottom: 16px;
      margin-bottom: 24px;
    }
    h1 {
      font-size: 24px;
      margin: 0 0 8px 0;
      color: #fff;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .badge {
      display: inline-block;
      padding: 3px 8px;
      font-size: 12px;
      font-weight: 600;
      border-radius: 20px;
      background: rgba(88, 166, 255, 0.15);
      color: var(--accent);
      border: 1px solid rgba(88, 166, 255, 0.3);
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 24px;
    }
    label {
      display: block;
      font-weight: 600;
      margin-bottom: 8px;
      color: #fff;
    }
    textarea, input {
      width: 100%;
      box-sizing: border-box;
      background: #0d1117;
      border: 1px solid var(--border);
      color: var(--text);
      padding: 10px;
      border-radius: 6px;
      font-family: monospace;
      font-size: 13px;
      margin-bottom: 12px;
    }
    button {
      background: #238636;
      color: #fff;
      border: none;
      padding: 10px 20px;
      font-size: 14px;
      font-weight: 600;
      border-radius: 6px;
      cursor: pointer;
      transition: background 0.2s;
    }
    button:hover {
      background: #2ea043;
    }
    .result {
      margin-top: 16px;
      padding: 16px;
      border-radius: 6px;
      display: none;
    }
    .result.valid {
      background: rgba(63, 185, 80, 0.15);
      border: 1px solid var(--success);
      color: #fff;
    }
    .result.invalid {
      background: rgba(248, 81, 73, 0.15);
      border: 1px solid var(--danger);
      color: #fff;
    }
    pre {
      margin: 0;
      overflow-x: auto;
      font-family: monospace;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>🛡️ Global Audit Logger <span class="badge">Zero-Trust Verification Portal</span></h1>
      <p style="color: var(--text-muted); margin: 0;">Independently verify cryptographic inclusion proofs and Ed25519 digital signatures without internal database access.</p>
    </header>

    <div class="card">
      <label for="proofInput">Paste Proof Document JSON:</label>
      <textarea id="proofInput" rows="10" placeholder='{
  "record": { "id": "rec-123", "table_name": "payments", ... },
  "proof": [ { "hash": "...", "is_left": false } ],
  "merkle_root_hex": "5e8848...",
  "signature_hex": "a4b9c8...",
  "key_version": "v1"
}'></textarea>
      <button onclick="verifyProof()">Verify Proof Authenticity</button>

      <div id="resultBox" class="result">
        <strong id="resultTitle"></strong>
        <p id="resultMsg" style="margin: 8px 0 0 0;"></p>
      </div>
    </div>

    <div class="card">
      <label>Published Endpoints (Open Access):</label>
      <ul>
        <li><a href="/public/verification/keys" target="_blank" style="color: var(--accent);"><code>/public/verification/keys</code></a> — Active & historical Ed25519 public keys</li>
        <li><a href="/public/verification/roots" target="_blank" style="color: var(--accent);"><code>/public/verification/roots</code></a> — Published signed Merkle roots archive</li>
        <li><a href="/health" target="_blank" style="color: var(--accent);"><code>/health</code></a> — Health status</li>
      </ul>
    </div>
  </div>

  <script>
    async function verifyProof() {
      const input = document.getElementById("proofInput").value.trim();
      const box = document.getElementById("resultBox");
      const title = document.getElementById("resultTitle");
      const msg = document.getElementById("resultMsg");

      if (!input) {
        alert("Please paste a valid proof JSON document");
        return;
      }

      try {
        const payload = JSON.parse(input);
        const resp = await fetch("/public/verification/verify", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });
        const data = await resp.json();

        box.style.display = "block";
        if (data.valid) {
          box.className = "result valid";
          title.textContent = "✅ RECORD AUTHENTIC & UNTAMPERED (VALID)";
          msg.textContent = "The record data mathematically hashes into the published batch root and the digital signature is valid. Verified at: " + (data.verified_at || new Date().toISOString());
        } else {
          box.className = "result invalid";
          title.textContent = "❌ VERIFICATION FAILED (TAMPER DETECTED / INVALID)";
          msg.textContent = "Failure reason: " + (data.failure_reason || "Signature or Merkle path mismatch");
        }
      } catch (err) {
        box.style.display = "block";
        box.className = "result invalid";
        title.textContent = "❌ JSON Parse Error";
        msg.textContent = err.message;
      }
    }
  </script>
</body>
</html>`

// PortalHandler serves the interactive zero-trust verification webpage.
func (h *Handler) PortalHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(portalHTML))
}
