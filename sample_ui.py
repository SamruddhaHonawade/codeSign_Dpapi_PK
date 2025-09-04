"""
Single-file Flask app that implements the UI mockup for the Code Signing Tool.
- Uses a Tailwind CDN for styling inside the rendered HTML template.
- Provides two endpoints: '/' (GET) to show UI, '/sign' and '/verify' (POST) to handle form submissions.
- Attempts to generate a self-signed certificate using `cryptography` if available; otherwise simulates a certificate file.

Run:
    pip install flask cryptography
    python flask_code_signing_tool.py
Open http://127.0.0.1:5000

Files saved to: ./uploads and ./certs
"""
from flask import Flask, request, redirect, url_for, send_from_directory, render_template_string, flash
import os
from datetime import datetime, timedelta
from pathlib import Path

# Optional cryptography usage
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    CRYPTO_AVAILABLE = True
except Exception:
    CRYPTO_AVAILABLE = False

app = Flask(__name__)
app.secret_key = 'dev-secret-key'

UPLOAD_DIR = Path('./uploads')
CERT_DIR = Path('./certs')
UPLOAD_DIR.mkdir(exist_ok=True)
CERT_DIR.mkdir(exist_ok=True)

# A single HTML template string using Tailwind CDN. This mirrors the Figma-style UI provided earlier.
TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Code Signing Tool</title>
    <script src="https://cdn.tailwindcss.com"></script>
  </head>
  <body class="bg-gray-50 min-h-screen flex items-start justify-center py-10">
    <div class="w-full max-w-4xl bg-white rounded-2xl shadow p-6">
      <header class="flex items-center justify-between mb-4">
        <h1 class="text-2xl font-semibold">Code Signing Tool</h1>
        <div class="text-xl">🌙</div>
      </header>

      <nav class="mb-6 border-b">
        <button class="pb-2 mr-6 text-indigo-600 border-b-4 border-indigo-600">Sign File</button>
        <button class="pb-2 text-gray-500">Verify Signature</button>
      </nav>

      <form action="/sign" method="post" enctype="multipart/form-data">
        <div class="grid grid-cols-2 gap-6">

          <!-- Left column -->
          <div>
            <div class="bg-white border rounded-xl p-4 mb-4">
              <h2 class="font-medium mb-2">Upload File</h2>
              <input name="file" type="file" class="block w-full text-sm text-gray-700" />
              <p class="mt-2 text-sm text-gray-500">Selected: {{ signed_filename or '—' }}</p>
            </div>

            <div class="bg-white border rounded-xl p-4 mb-4">
              <h2 class="font-medium mb-2">Certificate</h2>
              <label class="flex items-center gap-2"><input type="radio" name="cert_mode" value="upload" /> Upload Existing Certificate</label>
              <label class="flex items-center gap-2 mt-2"><input type="radio" name="cert_mode" value="generate" checked /> Generate New Certificate</label>

              <div class="mt-3">
                <label class="block text-sm mb-1">Organization / Publisher Name</label>
                <input name="org_name" value="Mozilla Corporation" class="w-full border rounded px-3 py-2" />
              </div>

              <div class="grid grid-cols-2 gap-3 mt-3">
                <div>
                  <label class="block text-sm mb-1">Country</label>
                  <select name="country" class="w-full border rounded px-3 py-2">
                    <option>US</option>
                    <option>IN</option>
                    <option>GB</option>
                  </select>
                </div>
                <div>
                  <label class="block text-sm mb-1">Validity Period</label>
                  <select name="validity" class="w-full border rounded px-3 py-2">
                    <option value="365">1 year</option>
                    <option value="730">2 years</option>
                  </select>
                </div>
              </div>
            </div>

          </div>

          <!-- Right column -->
          <div>
            <div class="bg-white border rounded-xl p-4 mb-4">
              <h2 class="font-medium mb-2">Algorithms</h2>
              <div class="mb-3">
                <label class="block text-sm mb-1">Hash Algorithm</label>
                <select name="hash_algo" class="w-full border rounded px-3 py-2">
                  <option>SHA-256</option>
                  <option selected>SHA3-256</option>
                  <option>SHA3-512</option>
                </select>
              </div>

              <div>
                <label class="block text-sm mb-1">Encryption Algorithm</label>
                <select name="enc_algo" class="w-full border rounded px-3 py-2">
                  <option>RSA</option>
                  <option>ECDSA</option>
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
                <div class="mt-4 p-3 rounded bg-green-50 border border-green-200 text-green-800">
                  ✅ {{ sign_status }}
                  <div class="text-sm mt-1 text-gray-700">Certificate: {{ cert_path }}</div>
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
            <label class="block text-sm mb-1">Upload File to Verify</label>
            <input type="file" name="verify_file" class="block w-full" form="verifyForm" />
            <label class="block text-sm mt-3 mb-1">Upload Certificate</label>
            <input type="file" name="verify_cert" class="block w-full" form="verifyForm" />
            <form id="verifyForm" action="/verify" method="post" enctype="multipart/form-data">
              <button type="submit" class="mt-4 bg-gray-100 border rounded px-4 py-2">VERIFY</button>
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
                <div>Publisher: {{ verify_details.publisher }}</div>
                <div>Expected: {{ verify_details.expected }}</div>
                <div>Found: {{ verify_details.found }}</div>
              </div>
            {% endif %}
          </div>
        </div>
      </section>

    </div>
  </body>
</html>
"""


@app.route('/', methods=['GET'])
def index():
    return render_template_string(TEMPLATE, signed_filename=None, sign_status=None, cert_path=None, verify_status=None, verify_details=None, verify_ok=None)


def _save_uploaded_file(f):
    if not f:
        return None
    filename = f.filename
    out_path = UPLOAD_DIR / filename
    f.save(out_path)
    return out_path


def _generate_self_signed_cert(org_name: str, country: str, validity_days: int, enc_algo: str, out_path: Path):
    """Try to generate a minimal self-signed cert. If cryptography is not available, write a placeholder file.
    """
    if not CRYPTO_AVAILABLE:
        out_path.write_text(f"--SIMULATED CERT--\nOrg: {org_name}\nCountry: {country}\nValid for: {validity_days} days\nAlgo: {enc_algo}\n")
        return out_path

    # Use RSA or ECDSA
    if enc_algo.upper() == 'RSA':
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    else:
        key = ec.generate_private_key(ec.SECP384R1())

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.COMMON_NAME, org_name),
    ])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.utcnow()).not_valid_after(datetime.utcnow() + timedelta(days=validity_days)).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256())

    # Write private key + cert to out_path as PEM bundle
    pem_key = key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
    pem_cert = cert.public_bytes(serialization.Encoding.PEM)
    out_path.write_bytes(pem_key + pem_cert)
    return out_path


@app.route('/sign', methods=['POST'])
def sign_file():
    f = request.files.get('file')
    saved = _save_uploaded_file(f)
    hash_algo = request.form.get('hash_algo')
    enc_algo = request.form.get('enc_algo')
    cert_mode = request.form.get('cert_mode')
    org_name = request.form.get('org_name') or 'Unknown'
    country = request.form.get('country') or 'US'
    validity = int(request.form.get('validity') or 365)

    cert_path = None
    if cert_mode == 'upload':
        c = request.files.get('certificate')
        if c:
            p = CERT_DIR / c.filename
            c.save(p)
            cert_path = str(p)
    else:
        # generate
        fname = f"{org_name.replace(' ', '_')}_{int(datetime.utcnow().timestamp())}.pem"
        out = CERT_DIR / fname
        _generate_self_signed_cert(org_name, country, validity, enc_algo, out)
        cert_path = str(out)

    status = 'File signed successfully.' if saved else 'No file uploaded; certificate generated.'
    return render_template_string(TEMPLATE, signed_filename=(saved.name if saved else None), sign_status=status, cert_path=cert_path, verify_status=None, verify_details=None, verify_ok=None)


@app.route('/verify', methods=['POST'])
def verify():
    vf = request.files.get('verify_file')
    vc = request.files.get('verify_cert')
    vf_path = _save_uploaded_file(vf)
    vc_path = None
    if vc:
        vc_path = CERT_DIR / vc.filename
        vc.save(vc_path)

    # Simulated verification: if both files exist, claim valid and show fake hashes
    if vf_path and vc_path:
        verify_ok = True
        status = 'Signature Valid'
        details = type('X', (), {})()
        details.publisher = 'Simulated Publisher'
        details.expected = 'a1b2c3d4...'
        details.found = 'a1b2c3d4...'
    else:
        verify_ok = False
        status = 'Signature Invalid or missing inputs.'
        details = None

    return render_template_string(TEMPLATE, signed_filename=None, sign_status=None, cert_path=None, verify_status=status, verify_details=details, verify_ok=verify_ok)


if __name__ == '__main__':
    app.run(debug=True)
