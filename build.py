#!/usr/bin/env python3
"""Wessling Family Archive — Baukasten.
Baut aus engine.html + data.json das fertige Archiv.

  python3 build.py            -> archiv_klar.html (unverschluesselt, nur lokal verwenden!)
  python3 build.py --encrypt  -> index.html (AES-verschluesselt, fuer den Webserver)

Passwort steht in config.json ("password").
"""
import json, sys, os, base64, hashlib, secrets

HERE = os.path.dirname(os.path.abspath(__file__))
ORDER = [("STRANDS","const"),("TAGS","const"),("PERSONS","const"),("SOURCES","const"),
         ("EVENTS","const"),("NARRATIVES","const"),("RELX","window"),("PHOTOS","window"),("IMGS","const"),("HEROES","window")]

def build_plain():
    data = json.load(open(os.path.join(HERE,"data.json"), encoding="utf-8"))
    engine = open(os.path.join(HERE,"engine.html"), encoding="utf-8").read()
    parts = []
    for name, kind in ORDER:
        js = json.dumps(data[name.lower()], ensure_ascii=False, separators=(", ", ": "))
        prefix = "const %s=" % name if kind == "const" else "window.%s=" % name
        parts.append(prefix + js + ";")
    blob = "\n".join(parts)
    assert "/*__DATA__*/" in engine, "Marker /*__DATA__*/ fehlt in engine.html"
    return engine.replace("/*__DATA__*/", blob)

def encrypt(html, password):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 250000, 32)
    ct = AESGCM(key).encrypt(nonce, html.encode("utf-8"), None)
    b64 = base64.b64encode(salt + nonce + ct).decode()
    gate = open(os.path.join(HERE,"gate_template.html"), encoding="utf-8").read()
    assert "__B64__" in gate, "Marker __B64__ fehlt in gate_template.html"
    return gate.replace("__B64__", b64)

if __name__ == "__main__":
    html = build_plain()
    if "--encrypt" in sys.argv:
        cfg = json.load(open(os.path.join(HERE,"config.json"), encoding="utf-8"))
        out = os.path.join(HERE, "index.html")
        open(out, "w", encoding="utf-8").write(encrypt(html, cfg["password"]))
        print("geschrieben:", out)
    else:
        out = os.path.join(HERE, "archiv_klar.html")
        open(out, "w", encoding="utf-8").write(html)
        print("geschrieben:", out, "(ACHTUNG: unverschluesselt, nicht hochladen)")
