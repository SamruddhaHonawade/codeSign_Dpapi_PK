"""
flask_code_signing_tool.py

Single-file Flask app — fully functional code signing + verification with 7-day certificate validity.

Features:
- Generate RSA (2048) or ECDSA (SECP384R1) key + self-signed cert (valid for 7 days).
- Sign uploaded file using chosen hash (SHA-256 / SHA3-256 / SHA3-512).
- Produce .sig and .meta.json alongside uploads.
- Verify signature using uploaded certificate/public key + .sig and check certificate timestamp validity.
- Serve downloads for uploads, certs, and sigs.

Usage:
    pip install flask cryptography
    python flask_code_signing_tool.py
    Visit http://127.0.0.1:5000
"""
from flask import Flask, request, render_template_string, url_for, send_from_directory
from pathlib import Path
from datetime import datetime, timedelta
import json
import traceback

# Try imports from cryptography
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
    from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    CRYPTO_AVAILABLE = True
except Exception:
    CRYPTO_AVAILABLE = False

app = Flask(__name__)
app.secret_key = "dev-secret-key"

BASE = Path('.')
UPLOADS = BASE / 'uploads'
CERTS = BASE / 'certs'
SIGS = BASE / 'sigs'
for d in (UPLOADS, CERTS, SIGS):
    d.mkdir(exist_ok=True)

# HTML template (Tailwind CDN) — uses render_template_string so this file is self-contained
TEMPLATE = r"""
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>Code Signing Tool</title>
    <script src="https://cdn.tailwindcss.com"></script>
  </head>
  <body class="bg-gray-50 min-h-screen flex items-start justify-center py-10">
    <div class="w-full max-w-4xl bg-white rounded-2xl shadow p-6">
      <header class="flex items-center justify-between mb-4">
        <h1 class="text-2xl font-semibold">Code Signing Tool</h1>
        <div class="text-xl">🔐</div>
      </header>

      <nav class="mb-6 border-b pb-4">
        <button class="pb-2 mr-6 text-indigo-600 border-b-4 border-indigo-600">Sign File</button>
        <button class="pb-2 text-gray-500">Verify Signature</button>
      </nav>

      <form action="{{ url_for('sign') }}" method="post" enctype="multipart/form-data" class="mb-6">
        <div class="grid grid-cols-2 gap-6">

          <!-- Left -->
          <div>
            <div class="bg-white border rounded-xl p-4 mb-4">
              <h2 class="font-medium mb-2">Upload File to Sign</h2>
              <input name="file" type="file" class="block w-full text-sm text-gray-700" required />
            </div>

            <div class="bg-white border rounded-xl p-4 mb-4">
              <h2 class="font-medium mb-2">Certificate</h2>
              <label class="flex items-center gap-2"><input type="radio" name="cert_mode" value="upload" /> Upload Existing PEM (contains private key)</label>
              <label class="flex items-center gap-2 mt-2"><input type="radio" name="cert_mode" value="generate" checked /> Generate New Key & Certificate (7 days)</label>
              <div class="mt-3">
                <label class="block text-sm mb-1">Organization / Publisher Name</label>
                <input name="org_name" value="Mozilla Corporation" class="w-full border rounded px-3 py-2" />
              </div>
              <div class="mt-3">
                <label class="block text-sm mb-1">If Uploading PEM, choose file below</label>
                <input name="certificate" type="file" class="block w-full text-sm text-gray-700" />
              </div>
            </div>
          </div>

          <!-- Right -->
          <div>
            <div class="bg-white border rounded-xl p-4 mb-4">
              <h2 class="font-medium mb-2">Algorithms</h2>
              <div class="mb-3">
                <label class="block text-sm mb-1">Hash Algorithm</label>
                <select name="hash_algo" class="w-full border rounded px-3 py-2">
                  <option value="SHA-256">SHA-256</option>
                  <option value="SHA3-256" selected>SHA3-256</option>
                  <option value="SHA3-512">SHA3-512</option>
                </select>
              </div>

              <div>
                <label class="block text-sm mb-1">Signature Algorithm</label>
                <select name="enc_algo" class="w-full border rounded px-3 py-2">
                  <option value="RSA">RSA</option>
                  <option value="ECDSA">ECDSA</option>
                </select>
              </div>
            </div>

            <div class="bg-white border rounded-xl p-4">
              <h2 class="font-medium mb-2">Actions</h2>
              <div class="flex gap-3">
                <button type="submit" class="bg-indigo-600 text-white rounded px-5 py-2">SIGN FILE</button>
                <button type="reset" class="border rounded px-5 py-2">RESET</button>
              </div>

              {% if sign_status %}
                <div class="mt-4 p-3 rounded {{ 'bg-green-50 border-green-200 text-green-800' if sign_ok else 'bg-red-50 border-red-200 text-red-800' }}">
                  {{ sign_status }}
                  {% if cert_link %}
                    <div class="text-sm mt-1 text-gray-700">Certificate: <a class="underline" href="{{ cert_link }}">{{ cert_name }}</a></div>
                  {% endif %}
                  {% if sig_link %}
                    <div class="text-sm mt-1 text-gray-700">Signature: <a class="underline" href="{{ sig_link }}">{{ sig_name }}</a></div>
                  {% endif %}
                </div>
              {% endif %}
            </div>
          </div>

        </div>
      </form>

      <section class="mt-8">
        <h3 class="text-lg font-semibold mb-3">Verify Signature</h3>
        <div class="grid grid-cols-2 gap-6">
          <div class="bg-white border rounded-xl p-4">
            <form id="verifyForm" action="{{ url_for('verify') }}" method="post" enctype="multipart/form-data">
              <label class="block text-sm mb-1">Upload File to Verify</label>
              <input type="file" name="verify_file" class="block w-full mb-3" required />
              <label class="block text-sm mb-1">Upload Certificate / Public Key (PEM)</label>
              <input type="file" name="verify_cert" class="block w-full mb-3" required />
              <label class="block text-sm mb-1">Upload Signature (.sig)</label>
              <input type="file" name="verify_sig" class="block w-full mb-3" required />
              <button type="submit" class="mt-2 bg-gray-100 border rounded px-4 py-2">VERIFY</button>
            </form>
          </div>

          <div class="bg-white border rounded-xl p-4">
            <h4 class="font-medium">Verification Result</h4>
            {% if verify_status %}
              <div class="mt-3 p-3 rounded {{ 'bg-green-50 border-green-200 text-green-800' if verify_ok else 'bg-red-50 border-red-200 text-red-800' }}">
                {{ verify_status }}
              </div>
            {% else %}
              <div class="mt-3 text-sm text-gray-500">No verification performed yet.</div>
            {% endif %}

            {% if verify_details %}
              <div class="mt-3 text-sm text-gray-700">
                <div>Publisher: {{ verify_details.publisher or '—' }}</div>
                <div>Cert valid until: {{ verify_details.valid_until or '—' }}</div>
                <div>Algorithm used: {{ verify_details.enc_algo or '—' }} / {{ verify_details.hash_algo or '—' }}</div>
              </div>
            {% endif %}
          </div>
        </div>
      </section>

      <footer class="mt-6 text-xs text-gray-500">
        Certificates generated by this demo are stored locally in <code>./certs</code> and are valid for 7 days.
        <br/>Do NOT use generated private keys in production.
      </footer>
    </div>
  </body>
</html>
"""

# ------------------ Helper functions ------------------

def _hash_obj_from_name(name: str):
    name = (name or '').upper()
    if 'SHA3-512' in name or 'SHA3_512' in name:
        return hashes.SHA3_512()
    if 'SHA3-256' in name or 'SHA3_256' in name:
        return hashes.SHA3_256()
    return hashes.SHA256()

def _generate_self_signed(org_name: str, enc_algo: str, validity_days: int = 7):
    """
    Generate a private key + self-signed certificate valid for `validity_days`.
    Return (private_key_obj, cert_path (Path), cert_obj)
    """
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography library is required for key/cert generation.")

    enc = (enc_algo or 'RSA').upper()
    if enc == 'RSA':
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    else:
        priv = ec.generate_private_key(ec.SECP384R1())

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.COMMON_NAME, org_name),
    ])

    now = datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(priv, hashes.SHA256())
    )

    # Write combined PEM (private key + cert) for convenience (private first)
    timestamp = int(now.timestamp())
    fname = f"{org_name.replace(' ', '_')}_{timestamp}.pem"
    out_path = CERTS / fname

    pem_key = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem_cert = cert.public_bytes(serialization.Encoding.PEM)
    out_path.write_bytes(pem_key + pem_cert)
    return priv, out_path, cert

def _save_uploaded_file(field_storage, dest_dir: Path):
    if not field_storage:
        return None
    out = dest_dir / field_storage.filename
    field_storage.save(out)
    return out

def _load_private_key_from_pem_bytes(pem_bytes: bytes):
    try:
        return load_pem_private_key(pem_bytes, password=None)
    except Exception:
        return None

def _load_cert_from_pem_bytes(pem_bytes: bytes):
    try:
        return x509.load_pem_x509_certificate(pem_bytes)
    except Exception:
        return None

def _sign_data_with_private_key(private_key, data: bytes, enc_algo: str, hash_name: str):
    h = _hash_obj_from_name(hash_name)
    enc = (enc_algo or 'RSA').upper()
    if enc == 'RSA':
        # PKCS1 v1.5
        return private_key.sign(data, padding.PKCS1v15(), h)
    else:
        # ECDSA uses signature format from cryptography (ASN.1 DER)
        return private_key.sign(data, ECDSA(h))

def _verify_with_public_key(public_key, data: bytes, signature: bytes, enc_algo: str, hash_name: str):
    h = _hash_obj_from_name(hash_name)
    enc = (enc_algo or 'RSA').upper()
    try:
        if enc == 'RSA':
            public_key.verify(signature, data, padding.PKCS1v15(), h)
        else:
            public_key.verify(signature, data, ECDSA(h))
        return True, None
    except Exception as e:
        return False, str(e)

def _write_meta(path: Path, meta: dict):
    path.write_text(json.dumps(meta, indent=2))

def _read_meta(path: Path):
    try:
        return json.loads(path.read_text())
    except Exception:
        return None

# ------------------ Routes ------------------

@app.route('/', methods=['GET'])
def index():
    return render_template_string(TEMPLATE,
                                  sign_status=None, sign_ok=False, cert_link=None, cert_name=None, sig_link=None, sig_name=None,
                                  verify_status=None, verify_ok=False, verify_details=None)

@app.route('/certs/<path:filename>')
def download_cert(filename):
    return send_from_directory(str(CERTS), filename, as_attachment=True)

@app.route('/uploads/<path:filename>')
def download_upload(filename):
    return send_from_directory(str(UPLOADS), filename, as_attachment=True)

@app.route('/sigs/<path:filename>')
def download_sig(filename):
    return send_from_directory(str(SIGS), filename, as_attachment=True)

@app.route('/sign', methods=['POST'])
def sign():
    try:
        if not CRYPTO_AVAILABLE:
            return render_template_string(TEMPLATE, sign_status="cryptography library not available (install 'cryptography')", sign_ok=False, cert_link=None, cert_name=None, sig_link=None, sig_name=None, verify_status=None, verify_ok=False, verify_details=None)

        file_field = request.files.get('file')
        if not file_field:
            return render_template_string(TEMPLATE, sign_status="No file uploaded.", sign_ok=False, cert_link=None, cert_name=None, sig_link=None, sig_name=None, verify_status=None, verify_ok=False, verify_details=None)

        saved = _save_uploaded_file(file_field, UPLOADS)
        enc_algo = request.form.get('enc_algo') or 'RSA'
        hash_algo = request.form.get('hash_algo') or 'SHA3-256'
        cert_mode = request.form.get('cert_mode') or 'generate'
        org_name = request.form.get('org_name') or 'Unknown'

        private_key = None
        cert_path = None
        cert_obj = None

        if cert_mode == 'upload':
            cert_upload = request.files.get('certificate')
            if not cert_upload:
                return render_template_string(TEMPLATE, sign_status="Selected upload mode but no PEM uploaded.", sign_ok=False, cert_link=None, cert_name=None, sig_link=None, sig_name=None, verify_status=None, verify_ok=False, verify_details=None)
            cert_path = _save_uploaded_file(cert_upload, CERTS)
            pem = cert_path.read_bytes()
            # Try to load private key (PEM with private key)
            private_key = _load_private_key_from_pem_bytes(pem)
            # Try to load certificate (some uploads may be only cert)
            cert_obj = _load_cert_from_pem_bytes(pem)
            if private_key is None and cert_obj is None:
                return render_template_string(TEMPLATE, sign_status="Uploaded PEM not recognized as private key or certificate.", sign_ok=False, cert_link=None, cert_name=None, sig_link=None, sig_name=None, verify_status=None, verify_ok=False, verify_details=None)
        else:
            # generate fresh key+cert (valid for 7 days)
            private_key, cert_path, cert_obj = _generate_self_signed(org_name, enc_algo, validity_days=7)

        if private_key is None:
            # Cannot sign without private key
            return render_template_string(TEMPLATE, sign_status="No private key available to sign (upload a PEM with private key or choose Generate New).", sign_ok=False, cert_link=(url_for('download_cert', filename=cert_path.name) if cert_path else None), cert_name=(cert_path.name if cert_path else None), sig_link=None, sig_name=None, verify_status=None, verify_ok=False, verify_details=None)

        # Read file bytes and hash them according to chosen hash algorithm
        data = saved.read_bytes()
        # In this implementation we sign the raw file bytes (commonly you'd sign a hash or canonicalized content).
        signature = _sign_data_with_private_key(private_key, data, enc_algo, hash_algo)

        sig_name = saved.name + '.sig'
        sig_path = SIGS / sig_name
        sig_path.write_bytes(signature)

        # Save metadata for convenience
        meta = {
            "file": saved.name,
            "signature": sig_name,
            "cert": cert_path.name if cert_path else None,
            "enc_algo": enc_algo,
            "hash_algo": hash_algo,
            "signed_at": datetime.utcnow().isoformat() + 'Z'
        }
        meta_path = UPLOADS / (saved.name + '.meta.json')
        _write_meta(meta_path, meta)

        # Provide links
        cert_link = url_for('download_cert', filename=cert_path.name) if cert_path else None
        sig_link = url_for('download_sig', filename=sig_name)

        return render_template_string(TEMPLATE,
                                      sign_status="File signed successfully.",
                                      sign_ok=True,
                                      cert_link=cert_link,
                                      cert_name=(cert_path.name if cert_path else None),
                                      sig_link=sig_link,
                                      sig_name=sig_name,
                                      verify_status=None,
                                      verify_ok=False,
                                      verify_details=None)

    except Exception as e:
        tb = traceback.format_exc()
        return render_template_string(TEMPLATE, sign_status=f"Error during signing: {e}", sign_ok=False, cert_link=None, cert_name=None, sig_link=None, sig_name=None, verify_status=None, verify_ok=False, verify_details={"trace": tb})

@app.route('/verify', methods=['POST'])
def verify():
    try:
        if not CRYPTO_AVAILABLE:
            return render_template_string(TEMPLATE, verify_status="cryptography library not available (install 'cryptography')", verify_ok=False, verify_details=None, sign_status=None, sign_ok=False, cert_link=None, cert_name=None, sig_link=None, sig_name=None)

        vf = request.files.get('verify_file')
        vc = request.files.get('verify_cert')
        vs = request.files.get('verify_sig')

        if not (vf and vc and vs):
            return render_template_string(TEMPLATE, verify_status="Please upload file, certificate/public key (PEM), and signature (.sig).", verify_ok=False, verify_details=None, sign_status=None, sign_ok=False, cert_link=None, cert_name=None, sig_link=None, sig_name=None)

        vf_path = _save_uploaded_file(vf, UPLOADS)
        vc_path = _save_uploaded_file(vc, CERTS)
        vs_path = _save_uploaded_file(vs, SIGS)

        # Load certificate or public key
        cert_bytes = vc_path.read_bytes()
        cert_obj = _load_cert_from_pem_bytes(cert_bytes)
        public_key = None
        publisher = None
        valid_until = None

        if cert_obj:
            public_key = cert_obj.public_key()
            try:
                publisher = cert_obj.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
            except Exception:
                publisher = None
            valid_until = cert_obj.not_valid_after
        else:
            # try load public key or private key
            priv = _load_private_key_from_pem_bytes(cert_bytes)
            if priv:
                public_key = priv.public_key()
            else:
                try:
                    public_key = load_pem_public_key(cert_bytes)
                except Exception:
                    public_key = None

        if public_key is None:
            return render_template_string(TEMPLATE, verify_status="Could not load public key or certificate from uploaded PEM.", verify_ok=False, verify_details=None, sign_status=None, sign_ok=False, cert_link=None, cert_name=None, sig_link=None, sig_name=None)

        # Check cert validity (if certificate object was available)
        now = datetime.utcnow()
        if valid_until:
            if now > valid_until:
                return render_template_string(TEMPLATE,
                                              verify_status="Certificate has expired (not valid after {}). Verification aborted.".format(valid_until.isoformat()),
                                              verify_ok=False,
                                              verify_details={"publisher": publisher, "valid_until": valid_until.isoformat(), "enc_algo": None, "hash_algo": None},
                                              sign_status=None, sign_ok=False, cert_link=None, cert_name=None, sig_link=None, sig_name=None)

        # Try to load meta (optional) from same-named .meta.json in uploads to get enc/hash
        meta = None
        candidate_meta = UPLOADS / (vf_path.name + '.meta.json')
        if candidate_meta.exists():
            meta = _read_meta(candidate_meta)

        tried = []
        success = False
        details = {"publisher": publisher, "valid_until": (valid_until.isoformat() if valid_until else None)}
        data = vf_path.read_bytes()
        signature = vs_path.read_bytes()

        # If meta gives enc/hash, try them first
        if meta and meta.get('enc_algo') and meta.get('hash_algo'):
            enc = meta['enc_algo']
            h = meta['hash_algo']
            ok, msg = _verify_with_public_key(public_key, data, signature, enc, h)
            tried.append((enc, h, ok, msg))
            if ok:
                success = True
                details.update({"enc_algo": enc, "hash_algo": h})
        else:
            # try common combos
            combos = [
                ('RSA', 'SHA-256'),
                ('RSA', 'SHA3-256'),
                ('RSA', 'SHA3-512'),
                ('ECDSA', 'SHA-256'),
                ('ECDSA', 'SHA3-256'),
                ('ECDSA', 'SHA3-512'),
            ]
            for enc, h in combos:
                ok, msg = _verify_with_public_key(public_key, data, signature, enc, h)
                tried.append((enc, h, ok, msg))
                if ok:
                    success = True
                    details.update({"enc_algo": enc, "hash_algo": h})
                    break

        if success:
            return render_template_string(TEMPLATE, verify_status="Signature VALID ✅", verify_ok=True, verify_details=details, sign_status=None, sign_ok=False, cert_link=None, cert_name=None, sig_link=None, sig_name=None)
        else:
            errs = "; ".join([f"{e}/{h}: {'OK' if ok else 'ERR:'+ (msg or '')}" for e,h,ok,msg in tried])
            return render_template_string(TEMPLATE, verify_status=f"Signature INVALID ❌ (attempts: {errs})", verify_ok=False, verify_details=details, sign_status=None, sign_ok=False, cert_link=None, cert_name=None, sig_link=None, sig_name=None)

    except Exception as e:
        tb = traceback.format_exc()
        return render_template_string(TEMPLATE, verify_status=f"Error during verification: {e}", verify_ok=False, verify_details={"trace": tb}, sign_status=None, sign_ok=False, cert_link=None, cert_name=None, sig_link=None, sig_name=None)

# ------------------ Run ------------------
if __name__ == '__main__':
    if not CRYPTO_AVAILABLE:
        print("Warning: 'cryptography' is not available. Install it with: pip install cryptography")
    print("Starting Flask Code Signing Tool on http://127.0.0.1:5000")
    app.run(debug=True)
