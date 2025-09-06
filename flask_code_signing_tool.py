from flask import Flask, request, render_template, url_for, send_from_directory
from pathlib import Path
from datetime import datetime, timedelta
import json, traceback

# cryptography imports
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

app = Flask(__name__)
app.secret_key = "dev-secret-key"

BASE = Path('.')
UPLOADS, CERTS, SIGS = BASE/"uploads", BASE/"certs", BASE/"sigs"
for d in (UPLOADS, CERTS, SIGS):
    d.mkdir(exist_ok=True)

# ------------------ Helpers ------------------

def _hash_obj_from_name(name: str):
    n = (name or '').upper()
    if 'SHA3-512' in n: return hashes.SHA3_512()
    if 'SHA3-256' in n: return hashes.SHA3_256()
    return hashes.SHA256()

def _generate_self_signed(org, algo, days=7):
    if algo.upper() == "RSA":
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    else:
        priv = ec.generate_private_key(ec.SECP384R1())

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, org),
    ])

    now = datetime.utcnow()
    cert = (x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=days))
        .sign(priv, hashes.SHA256()))

    fname = f"{org.replace(' ','_')}_{int(now.timestamp())}.pem"
    out_path = CERTS / fname
    pem_key = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem_cert = cert.public_bytes(serialization.Encoding.PEM)
    out_path.write_bytes(pem_key + pem_cert)
    return priv, out_path, cert

def _save_uploaded_file(fs, dest):
    out = dest / fs.filename
    fs.save(out)
    return out

def _load_private_key(pem: bytes):
    try: return load_pem_private_key(pem, password=None)
    except: return None

def _load_cert(pem: bytes):
    try: return x509.load_pem_x509_certificate(pem)
    except: return None

def _sign(priv, data: bytes, algo, hname):
    h = _hash_obj_from_name(hname)
    return priv.sign(data, padding.PKCS1v15(), h) if algo.upper()=="RSA" else priv.sign(data, ECDSA(h))

def _verify(pub, data: bytes, sig: bytes, algo, hname):
    h = _hash_obj_from_name(hname)
    try:
        if algo.upper()=="RSA":
            pub.verify(sig, data, padding.PKCS1v15(), h)
        else:
            pub.verify(sig, data, ECDSA(h))
        return True, None
    except Exception as e:
        return False, str(e)

# ------------------ Routes ------------------

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/certs/<path:fn>')
def dl_cert(fn): return send_from_directory(str(CERTS), fn, as_attachment=True)

@app.route('/uploads/<path:fn>')
def dl_upload(fn): return send_from_directory(str(UPLOADS), fn, as_attachment=True)

@app.route('/sigs/<path:fn>')
def dl_sig(fn): return send_from_directory(str(SIGS), fn, as_attachment=True)

@app.route('/sign', methods=['POST'])
def sign():
    try:
        file = request.files['file']
        saved = _save_uploaded_file(file, UPLOADS)
        algo, hname = request.form['enc_algo'], request.form['hash_algo']
        mode, org = request.form['cert_mode'], request.form['org_name']

        if mode == "generate":
            priv, cert_path, cert = _generate_self_signed(org, algo)
        else:
            cert_file = request.files['certificate']
            cert_path = _save_uploaded_file(cert_file, CERTS)
            pem = cert_path.read_bytes()
            priv, cert = _load_private_key(pem), _load_cert(pem)

        if priv is None: raise ValueError("No private key available.")

        sig = _sign(priv, saved.read_bytes(), algo, hname)
        sig_path = SIGS / (saved.name + ".sig")
        sig_path.write_bytes(sig)

        meta = {
            "file": saved.name, "signature": sig_path.name,
            "cert": cert_path.name, "enc_algo": algo, "hash_algo": hname,
            "signed_at": datetime.utcnow().isoformat()+"Z"
        }
        (UPLOADS/(saved.name+".meta.json")).write_text(json.dumps(meta, indent=2))

        return render_template("index.html",
                               sign_status="File signed successfully ✅",
                               cert_name=cert_path.name, sig_name=sig_path.name)
    except Exception as e:
        return render_template("index.html", sign_status=f"Error: {e}")

@app.route('/verify', methods=['POST'])
def verify():
    try:
        vf, vc, vs = request.files['verify_file'], request.files['verify_cert'], request.files['verify_sig']
        vf_path, vc_path, vs_path = _save_uploaded_file(vf, UPLOADS), _save_uploaded_file(vc, CERTS), _save_uploaded_file(vs, SIGS)

        cert_bytes = vc_path.read_bytes()
        cert, pub = _load_cert(cert_bytes), None
        publisher, valid_until = None, None
        if cert:
            pub, publisher, valid_until = cert.public_key(), cert.subject.rfc4514_string(), cert.not_valid_after
        else:
            priv = _load_private_key(cert_bytes)
            pub = priv.public_key() if priv else load_pem_public_key(cert_bytes)

        data, sig = vf_path.read_bytes(), vs_path.read_bytes()
        meta_file = UPLOADS/(vf_path.name+".meta.json")
        enc, h = "RSA","SHA-256"
        if meta_file.exists():
            meta=json.loads(meta_file.read_text())
            enc,h=meta["enc_algo"],meta["hash_algo"]

        ok,_ = _verify(pub,data,sig,enc,h)
        if not ok: return render_template("index.html", verify_status="Signature INVALID ❌")

        ts = datetime.utcnow().isoformat()+"Z"
        return render_template("index.html",
                               verify_status=f"Signature VALID ✅ at {ts}",
                               publisher=publisher, valid_until=valid_until, enc_algo=enc, hash_algo=h)
    except Exception as e:
        return render_template("index.html", verify_status=f"Error: {e}")

if __name__ == "__main__":
    app.run(debug=True)
