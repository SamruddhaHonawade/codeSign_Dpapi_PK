import os
import datetime
from flask import Flask, render_template, request, send_from_directory, url_for
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["CERT_FOLDER"] = "certs"
app.config["SIG_FOLDER"] = "signatures"

# Ensure dirs exist
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
os.makedirs(app.config["CERT_FOLDER"], exist_ok=True)
os.makedirs(app.config["SIG_FOLDER"], exist_ok=True)


def generate_self_signed_cert(org_name, enc_algo, hash_algo):
    """Generate self-signed cert + private key"""
    if enc_algo == "RSA":
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    else:
        key = ec.generate_private_key(ec.SECP256R1())

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name or "DemoOrg"),
        x509.NameAttribute(NameOID.COMMON_NAME, "codesigner.local"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key=key, algorithm=hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    cert_path = os.path.join(app.config["CERT_FOLDER"], "certificate.pem")
    key_path = os.path.join(app.config["CERT_FOLDER"], "private_key.pem")

    with open(cert_path, "wb") as f: f.write(cert_pem)
    with open(key_path, "wb") as f: f.write(key_pem)

    return cert_path, key_path


def sign_file(file_path, key_path, hash_algo, enc_algo):
    """Sign file with private key"""
    with open(file_path, "rb") as f:
        data = f.read()
    with open(key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    digest_algo = hashes.SHA256() if hash_algo == "SHA-256" else hashes.SHA3_256()
    hasher = hashes.Hash(digest_algo)
    hasher.update(data)
    digest = hasher.finalize()

    if enc_algo == "RSA":
        signature = private_key.sign(digest, padding.PKCS1v15(), Prehashed(digest_algo))
    else:
        signature = private_key.sign(digest, ec.ECDSA(Prehashed(digest_algo)))

    sig_path = os.path.join(app.config["SIG_FOLDER"], os.path.basename(file_path) + ".sig")
    with open(sig_path, "wb") as f: f.write(signature)

    return sig_path


def verify_signature(file_path, cert_path, sig_path, hash_algo, enc_algo):
    """Verify signature using public key in cert"""
    with open(file_path, "rb") as f: data = f.read()
    with open(sig_path, "rb") as f: signature = f.read()
    with open(cert_path, "rb") as f: cert = x509.load_pem_x509_certificate(f.read())
    public_key = cert.public_key()

    digest_algo = hashes.SHA256() if hash_algo == "SHA-256" else hashes.SHA3_256()
    hasher = hashes.Hash(digest_algo)
    hasher.update(data)
    digest = hasher.finalize()

    try:
        if enc_algo == "RSA":
            public_key.verify(signature, digest, padding.PKCS1v15(), Prehashed(digest_algo))
        else:
            public_key.verify(signature, digest, ec.ECDSA(Prehashed(digest_algo)))
        return True
    except Exception:
        return False


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/sign", methods=["POST"])
def sign():
    file = request.files.get("file")
    cert_mode = request.form.get("cert_mode")
    org_name = request.form.get("org_name")
    hash_algo = request.form.get("hash_algo")
    enc_algo = request.form.get("enc_algo")

    if not file: return render_template("index.html", sign_status="❌ No file uploaded", sign_ok=False)

    file_path = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
    file.save(file_path)

    # Generate or use uploaded cert
    if cert_mode == "generate":
        cert_path, key_path = generate_self_signed_cert(org_name, enc_algo, hash_algo)
    else:
        cert = request.files.get("certificate")
        cert_path = os.path.join(app.config["CERT_FOLDER"], "uploaded_cert.pem")
        cert.save(cert_path)
        key_path = os.path.join(app.config["CERT_FOLDER"], "private_key.pem")

    sig_path = sign_file(file_path, key_path, hash_algo, enc_algo)

    return render_template(
        "index.html",
        sign_status="✅ File signed successfully",
        sign_ok=True,
        cert_link=url_for("download_cert", filename=os.path.basename(cert_path)),
        sig_link=url_for("download_sig", filename=os.path.basename(sig_path)),
        cert_name=os.path.basename(cert_path),
        sig_name=os.path.basename(sig_path),
    )


@app.route("/verify", methods=["POST"])
def verify():
    file = request.files.get("verify_file")
    cert = request.files.get("verify_cert")
    sig = request.files.get("verify_sig")

    if not (file and cert and sig):
        return render_template("index.html", verify_status="❌ Missing file/cert/sig", verify_ok=False)

    file_path = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
    cert_path = os.path.join(app.config["CERT_FOLDER"], cert.filename)
    sig_path = os.path.join(app.config["SIG_FOLDER"], sig.filename)

    file.save(file_path)
    cert.save(cert_path)
    sig.save(sig_path)

    # Defaulting to SHA-256/RSA for verify (could be extended to detect from cert)
    valid = verify_signature(file_path, cert_path, sig_path, "SHA-256", "RSA")

    return render_template(
        "index.html",
        verify_status="✅ Signature is VALID" if valid else "❌ Signature is INVALID",
        verify_ok=valid,
    )


@app.route("/certs/<filename>")
def download_cert(filename):
    return send_from_directory(app.config["CERT_FOLDER"], filename, as_attachment=True)


@app.route("/signatures/<filename>")
def download_sig(filename):
    return send_from_directory(app.config["SIG_FOLDER"], filename, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)
