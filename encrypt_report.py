#!/usr/bin/env python3
"""Şifreli yayın: rapor HTML'ini AES-GCM ile şifreleyip parola kapılı sayfa üretir.
Kullanım: python3 encrypt_report.py <girdi.html> <parola> <cikti.html>
"""
import base64, os, sys, json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

GATE = '''<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow">
<title>__TITLE__</title>
<style>
  :root { --surface:#fcfcfb; --page:#f9f9f7; --ink:#0b0b0b; --ink2:#52514e; --border:rgba(11,11,11,.12); --accent:#2a78d6; }
  @media (prefers-color-scheme: dark) { :root { --surface:#1a1a19; --page:#0d0d0d; --ink:#fff; --ink2:#c3c2b7; --border:rgba(255,255,255,.12); --accent:#3987e5; } }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; background: var(--page); color: var(--ink);
         min-height: 100vh; display: flex; align-items: center; justify-content: center; }
  .box { background: var(--surface); border: 1px solid var(--border); border-radius: 14px; padding: 32px 30px; width: min(92vw, 380px); text-align: center; }
  .box h1 { font-size: 17px; margin-bottom: 6px; }
  .box p { font-size: 13px; color: var(--ink2); margin-bottom: 18px; }
  input { width: 100%; padding: 11px 14px; font-size: 15px; border: 1px solid var(--border); border-radius: 9px;
          background: var(--page); color: var(--ink); outline: none; text-align: center; }
  input:focus { border-color: var(--accent); }
  button { width: 100%; margin-top: 12px; padding: 11px; font-size: 14px; font-weight: 600; border: none; border-radius: 9px;
           background: var(--accent); color: #fff; cursor: pointer; }
  .err { color: #d03b3b; font-size: 12.5px; margin-top: 10px; min-height: 16px; }
</style>
</head>
<body>
<div class="box">
  <h1>__TITLE__</h1>
  <p>Bu sayfa koruma altındadır. Devam etmek için ekip parolasını girin.</p>
  <input id="pw" type="password" placeholder="Parola" autofocus>
  <button id="go">Aç</button>
  <div class="err" id="err"></div>
</div>
<script>
var P = __PAYLOAD__;
function b64(s){ var bin = atob(s); var a = new Uint8Array(bin.length); for (var i=0;i<bin.length;i++) a[i]=bin.charCodeAt(i); return a; }
async function unlock(){
  var pw = document.getElementById('pw').value;
  var err = document.getElementById('err');
  err.textContent = '';
  if (!pw) return;
  try {
    var km = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
    var key = await crypto.subtle.deriveKey({name:'PBKDF2', salt:b64(P.salt), iterations:P.iter, hash:'SHA-256'}, km,
      {name:'AES-GCM', length:256}, false, ['decrypt']);
    var pt = await crypto.subtle.decrypt({name:'AES-GCM', iv:b64(P.nonce)}, key, b64(P.ct));
    document.open(); document.write(new TextDecoder().decode(pt)); document.close();
  } catch(e) { err.textContent = 'Parola hatalı, tekrar deneyin.'; }
}
document.getElementById('go').addEventListener('click', unlock);
document.getElementById('pw').addEventListener('keydown', function(e){ if (e.key === 'Enter') unlock(); });
</script>
</body>
</html>'''

def build(report_path, password, out_path, title="AJTTEK · TOFAŞ AI Flash Report"):
    data = open(report_path, 'rb').read()
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=150000).derive(password.encode())
    ct = AESGCM(key).encrypt(nonce, data, None)
    payload = {
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ct": base64.b64encode(ct).decode(),
        "iter": 150000,
    }
    html = GATE.replace('__TITLE__', title).replace('__PAYLOAD__', json.dumps(payload))
    open(out_path, 'w').write(html)
    print(f"OK {out_path} ({os.path.getsize(out_path)} bytes)")

if __name__ == '__main__':
    build(sys.argv[1], sys.argv[2], sys.argv[3])
