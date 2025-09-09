
import os
import json
import zipfile
import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, scrolledtext
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
import win32crypt  # for Windows DPAPI

#  backend modules
from signing import generate_keypair, sign_digest, load_private_key
from hashing import compute_sha3_256, compute_sha3_512
from certificate import create_self_signed_cert

# GUI
class CodeSignerApp(tb.Window):
    def __init__(self):
        super().__init__(themename="cyborg")
        self.title("🔐 Code Signing Tool")
        self.geometry("1000x700")  # Set default window size
        self.resizable(True, True)  # Make window resizable

        self.file_path = None
        self.zip_path = None
        self.private_key = None
        self.key_path = None
        self.hash_algo_var = None  # For hash algorithm selection

        self._create_widgets()

    def _create_widgets(self):
        notebook = tb.Notebook(self, bootstyle="primary")
        notebook.pack(fill=BOTH, expand=True, padx=15, pady=15)

        key_tab = tb.Frame(notebook)
        notebook.add(key_tab, text="🔑 Key Management")
        self._create_key_tab(key_tab)

        sign_tab = tb.Frame(notebook)
        notebook.add(sign_tab, text="✍️ Sign File")
        self._create_sign_tab(sign_tab)

        verify_tab = tb.Frame(notebook)
        notebook.add(verify_tab, text="🕵️ Verify Package")
        self._create_verify_tab(verify_tab)

        self.log_box = tk.Text(self, height=8, bg="#1e1e1e", fg="white", insertbackground="white")
        self.log_box.pack(fill=X, padx=15, pady=(0, 10))

    def _create_key_tab(self, parent):
        # Key status
        self.key_status = tb.Label(parent, text="No key loaded", bootstyle="warning")
        self.key_status.pack(pady=10)

        # Load existing key
        tb.Button(parent, text="Load Existing Key", bootstyle="primary",
                  command=self.load_key).pack(pady=5)

        # Generate new key section
        tb.Label(parent, text="Generate New Key", font=("Helvetica", 10, "bold")).pack(pady=(20, 5))

        tb.Label(parent, text="Select Algorithm").pack(pady=(5, 5))
        self.algo_var = tk.StringVar(value="RSA")
        tb.Combobox(parent, textvariable=self.algo_var, values=["RSA(2048)- Fast and Secured", "RSA(4096)- Slow and Higly Secured", "ECDSA(256)-Fast and Secured","ECDSA(512)-Slow and Higly Secured"],
                    state="readonly", width=20).pack()

        # Signer details
        details_frame = tb.LabelFrame(parent, text="Signer Details", bootstyle="info")
        details_frame.pack(pady=10, padx=10, fill=X)

        tb.Label(details_frame, text="Country Name (e.g., IN)").pack(anchor=W)
        self.country_entry = tb.Entry(details_frame, width=40)
        self.country_entry.insert(0, "IN")
        self.country_entry.pack(pady=2)

        tb.Label(details_frame, text="State or Province Name (e.g., Karnataka)").pack(anchor=W)
        self.state_entry = tb.Entry(details_frame, width=40)
        self.state_entry.insert(0, "Karnataka")
        self.state_entry.pack(pady=2)

        tb.Label(details_frame, text="Locality Name (e.g., Bengaluru)").pack(anchor=W)
        self.locality_entry = tb.Entry(details_frame, width=40)
        self.locality_entry.insert(0, "Bengaluru")
        self.locality_entry.pack(pady=2)

        tb.Label(details_frame, text="Organization Name (e.g., MyCompany Pvt Ltd)").pack(anchor=W)
        self.org_entry = tb.Entry(details_frame, width=40)
        self.org_entry.insert(0, "MyCompany Pvt Ltd")
        self.org_entry.pack(pady=2)

        tb.Label(details_frame, text="Organizational Unit Name (e.g., Software Division)").pack(anchor=W)
        self.org_unit_entry = tb.Entry(details_frame, width=40)
        self.org_unit_entry.insert(0, "Software Division")
        self.org_unit_entry.pack(pady=2)

        tb.Label(details_frame, text="Common Name (Publisher)").pack(anchor=W)
        self.common_name_entry = tb.Entry(details_frame, width=40)
        self.common_name_entry.insert(0, "My Company Inc.")
        self.common_name_entry.pack(pady=2)

        tb.Label(details_frame, text="Email Address (e.g., support@mycompany.com)").pack(anchor=W)
        self.email_entry = tb.Entry(details_frame, width=40)
        self.email_entry.insert(0, "support@mycompany.com")
        self.email_entry.pack(pady=2)

        tb.Label(details_frame, text="Validity Days (e.g., 365)").pack(anchor=W)
        self.valid_days_entry = tb.Entry(details_frame, width=40)
        self.valid_days_entry.insert(0, "365")
        self.valid_days_entry.pack(pady=2)

        tb.Button(parent, text="Generate Key", bootstyle="success",
                  command=self.generate_key).pack(pady=10)

    def _create_sign_tab(self, parent):
        self.file_label = tb.Label(parent, text="No file selected", bootstyle="secondary")
        self.file_label.pack(pady=10)
        tb.Button(parent, text="Choose File", bootstyle="primary", command=self.choose_file).pack()

        # Hash algorithm selection
        tb.Label(parent, text="Select Hash Algorithm").pack(pady=(10, 5))
        self.hash_algo_var = tk.StringVar(value="SHA3-256")
        tb.Combobox(parent, textvariable=self.hash_algo_var, values=["SHA3-256", "SHA3-512"],
                    state="readonly", width=20).pack()

        tb.Button(parent, text="Sign & Create ZIP", bootstyle="success", command=self.sign_file).pack(pady=20)
        self.sign_status = tb.Label(parent, text="", bootstyle="info")
        self.sign_status.pack()

    def _create_verify_tab(self, parent):
        self.zip_label = tb.Label(parent, text="No package selected", bootstyle="secondary")
        self.zip_label.pack(pady=10)
        tb.Button(parent, text="Choose ZIP", bootstyle="primary", command=self.choose_zip).pack()
        tb.Button(parent, text="Verify", bootstyle="success", command=self.verify_zip).pack(pady=15)
        self.verify_status = tb.Label(parent, text="", bootstyle="warning")
        self.verify_status.pack()

        # Details display
        self.details_text = scrolledtext.ScrolledText(parent, height=10, wrap=tk.WORD)
        self.details_text.pack(pady=10, fill=BOTH, expand=True)
        self.details_text.config(state=tk.DISABLED)

    def log(self, msg):
        self.log_box.insert("end", f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {msg}\n")
        self.log_box.see("end")

    def load_key(self):
        try:
            key_path = filedialog.askopenfilename(
                title="Select protected private key file",
                filetypes=[("Key files", "*.key")]
            )
            if not key_path:
                self.log("Key selection cancelled.")
                return

            # Read encrypted data
            with open(key_path, "rb") as key_file:
                encrypted_pem = key_file.read()

            # Decrypt using DPAPI
            self.log("Decrypting key with Windows DPAPI...")
            _, pem = win32crypt.CryptUnprotectData(encrypted_pem, None, None, None, 0)  # Returns (desc, data)

            # Load the private key from decrypted PEM (no password)
            self.private_key = serialization.load_pem_private_key(
                pem,
                password=None,
                backend=default_backend()
            )

            # Detect algorithm
            algo = None
            if isinstance(self.private_key, rsa.RSAPrivateKey):
                algo = "RSA"
            elif isinstance(self.private_key, ec.EllipticCurvePrivateKey):
                algo = "ECDSA"
            else:
                raise ValueError("Unsupported key type")

            self.algo_var.set(algo)
            self.key_status.config(text=f"✅ {algo} Key loaded from {os.path.basename(key_path)} (DPAPI protected)", bootstyle="success")
            self.log(f"Private key loaded from {key_path}. Detected algorithm: {algo}")

            self.key_path = key_path

            # Load signer details if available
            json_path = key_path + '.json'
            if os.path.exists(json_path):
                with open(json_path, 'r') as json_file:
                    details = json.load(json_file)
                    self.country_entry.delete(0, tk.END)
                    self.country_entry.insert(0, details.get('country', 'IN'))
                    self.state_entry.delete(0, tk.END)
                    self.state_entry.insert(0, details.get('state', 'Karnataka'))
                    self.locality_entry.delete(0, tk.END)
                    self.locality_entry.insert(0, details.get('locality', 'Bengaluru'))
                    self.org_entry.delete(0, tk.END)
                    self.org_entry.insert(0, details.get('organization', 'MyCompany Pvt Ltd'))
                    self.org_unit_entry.delete(0, tk.END)
                    self.org_unit_entry.insert(0, details.get('org_unit', 'Software Division'))
                    self.common_name_entry.delete(0, tk.END)
                    self.common_name_entry.insert(0, details.get('common_name', 'My Company Inc.'))
                    self.email_entry.delete(0, tk.END)
                    self.email_entry.insert(0, details.get('email', 'support@mycompany.com'))
                    self.valid_days_entry.delete(0, tk.END)
                    self.valid_days_entry.insert(0, details.get('valid_days', '365'))
                self.log(f"Signer details loaded from {json_path}.")
            else:
                self.log("No signer details file found. Using defaults.")

        except Exception as e:
            self.log(f"ERROR loading key: {str(e)}")
            messagebox.showerror("Key Load Error", f"Failed to load key: {str(e)}")

    def generate_key(self):
        try:
            country = self.country_entry.get()
            state = self.state_entry.get()
            locality = self.locality_entry.get()
            org = self.org_entry.get()
            org_unit = self.org_unit_entry.get()
            common_name = self.common_name_entry.get()
            email = self.email_entry.get()
            valid_days_str = self.valid_days_entry.get()

            if not all([country, state, locality, org, org_unit, common_name, email, valid_days_str]):
                messagebox.showerror("Error", "All signer details must be filled.")
                self.log("ERROR: All signer details must be filled.")
                return
            if not valid_days_str.isdigit() or int(valid_days_str) <= 0:
                messagebox.showerror("Error", "Validity days must be a positive integer.")
                self.log("ERROR: Validity days must be a positive integer.")
                return

            algo = self.algo_var.get()
            self.log(f"Generating {algo} keypair...")
            self.private_key = generate_keypair(algo)

            # Serialize private key without password encryption
            pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

            # Encrypt with DPAPI (user-specific by default)
            self.log("Encrypting key with Windows DPAPI...")
            encrypted_pem = win32crypt.CryptProtectData(pem, None, None, None, None, 0)

            # Save details for later
            details = {
                "country": country,
                "state": state,
                "locality": locality,
                "organization": org,
                "org_unit": org_unit,
                "common_name": common_name,
                "email": email,
                "valid_days": valid_days_str
            }

            # Prompt for save location
            save_path = filedialog.asksaveasfilename(
                defaultextension=".key",
                filetypes=[("Key files", "*.key")],
                title="Save Protected Private Key"
            )
            if not save_path:
                self.log("Key saving cancelled.")
                self.key_status.config(text=f"✅ {algo} Key generated (not saved)", bootstyle="success")
                return

            # Save encrypted key
            with open(save_path, "wb") as f:
                f.write(encrypted_pem)
            self.log(f"Private key saved to {save_path} (DPAPI protected).")

            # Save signer details as JSON
            json_path = save_path + '.json'
            with open(json_path, "w") as f:
                json.dump(details, f, indent=2)
            self.log(f"Signer details saved to {json_path}.")
            self.key_path = save_path
            self.key_status.config(text=f"✅ {algo} Key generated and saved to {os.path.basename(save_path)} (DPAPI protected)", bootstyle="success")

        except Exception as e:
            self.log(f"ERROR generating key: {str(e)}")
            messagebox.showerror("Key Generation Error", str(e))

    def choose_file(self):
        path = filedialog.askopenfilename(title="Select file to sign")
        if path:
            self.file_path = path
            self.file_label.config(text=os.path.basename(path))
            self.log(f"File selected: {path}")
        else:
            self.log("File selection cancelled.")

    def choose_zip(self):
        path = filedialog.askopenfilename(title="Select signed package", filetypes=[("ZIP files", "*.zip")])
        if path:
            self.zip_path = path
            self.zip_label.config(text=os.path.basename(path))
            self.log(f"Package selected: {path}")
        else:
            self.log("Package selection cancelled.")

    def sign_file(self):
        if not self.file_path:
            messagebox.showerror("Error", "Select a file first.")
            self.log("ERROR: No file selected for signing.")
            return

        if not self.private_key:
            messagebox.showerror("Error", "No private key loaded. Please load or generate a key first.")
            self.log("ERROR: No private key loaded.")
            return

        country = self.country_entry.get()
        state = self.state_entry.get()
        locality = self.locality_entry.get()
        org = self.org_entry.get()
        org_unit = self.org_unit_entry.get()
        common_name = self.common_name_entry.get()
        email = self.email_entry.get()
        valid_days_str = self.valid_days_entry.get()

        if not all([country, state, locality, org, org_unit, common_name, email, valid_days_str]):
            messagebox.showerror("Error", "All signer details must be filled.")
            self.log("ERROR: All signer details must be filled.")
            return
        if not valid_days_str.isdigit() or int(valid_days_str) <= 0:
            messagebox.showerror("Error", "Validity days must be a positive integer.")
            self.log("ERROR: Validity days must be a positive integer.")
            return

        valid_days = int(valid_days_str)
        hash_algo = self.hash_algo_var.get().lower().replace("-", "_")  # Convert to "sha3_256" or "sha3_512"

        try:
            self.log(f"Reading file: {self.file_path}")
            with open(self.file_path, "rb") as f:
                file_bytes = f.read()

            self.log(f"Computing {hash_algo} digest...")
            digest = compute_sha3_256(file_bytes) if hash_algo == "sha3_256" else compute_sha3_512(file_bytes)
            algo = self.algo_var.get()

            self.log(f"Signing digest with {algo} and {hash_algo}...")
            sig = sign_digest(self.private_key, algo, digest, hash_algo=hash_algo)

            self.log("Creating self-signed certificate...")
            cert = create_self_signed_cert(
                private_key=self.private_key,
                country=country,
                state=state,
                locality=locality,
                organization=org,
                org_unit=org_unit,
                common_name=common_name,
                email=email,
                valid_days=valid_days
            )
            cert_pem = cert.public_bytes(serialization.Encoding.PEM)

            metadata = {
                "algorithm": algo,
                "hash_algorithm": hash_algo,
                "hash": digest.hex(),
                "signed_by": common_name,
                "signed_at": datetime.datetime.utcnow().isoformat()
            }

            self.log("Prompting for ZIP save location...")
            outpath = filedialog.asksaveasfilename(
                defaultextension=".zip",
                initialfile=f"signed_{os.path.basename(self.file_path)}.zip",
                filetypes=[("ZIP files", "*.zip")]
            )
            if not outpath:
                self.log("ZIP saving cancelled by user.")
                self.sign_status.config(text="⚠️ Signing cancelled", bootstyle="warning")
                return

            self.log(f"Creating ZIP file at {outpath}...")
            try:
                with zipfile.ZipFile(outpath, "w", zipfile.ZIP_DEFLATED) as z:
                    self.log(f"Writing file: {os.path.basename(self.file_path)}")
                    z.writestr(os.path.basename(self.file_path), file_bytes)
                    self.log("Writing signature.bin")
                    z.writestr("signature.bin", sig)
                    self.log("Writing certificate.pem")
                    z.writestr("certificate.pem", cert_pem)
                    self.log("Writing metadata.json")
                    z.writestr("metadata.json", json.dumps(metadata, indent=2))
                self.sign_status.config(text="✅ Signed Successfully!", bootstyle="success")
                self.log(f"Signed {self.file_path} -> {outpath}")
            except Exception as e:
                self.log(f"ERROR writing ZIP file: {str(e)}")
                messagebox.showerror("ZIP Creation Error", f"Failed to create ZIP file: {str(e)}")
                return

        except Exception as e:
            self.log(f"ERROR during signing: {str(e)}")
            messagebox.showerror("Signing Error", str(e))

    def verify_zip(self):
        if not self.zip_path:
            messagebox.showerror("Error", "Select a package first.")
            self.log("ERROR: No package selected for verification.")
            return

        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        self.details_text.config(state=tk.DISABLED)

        try:
            self.log(f"Opening ZIP file: {self.zip_path}")
            with zipfile.ZipFile(self.zip_path, "r") as z:
                filenames = z.namelist()
                required_files = {"signature.bin", "metadata.json", "certificate.pem"}
                if not required_files.issubset(filenames):
                    raise FileNotFoundError("Package is missing required signature files.")

                self.log("Reading metadata.json")
                meta = json.loads(z.read("metadata.json"))
                algo = meta["algorithm"]
                hash_algo = meta.get("hash_algorithm", "sha3_256")  # Default to sha3_256 for backward compatibility
                self.log("Reading signature.bin")
                sig = z.read("signature.bin")
                self.log("Reading certificate.pem")
                cert_data = z.read("certificate.pem")

                content_file_name = [n for n in filenames if n not in required_files][0]
                self.log(f"Reading content file: {content_file_name}")
                file_bytes = z.read(content_file_name)

                self.log(f"Verifying {content_file_name} using {algo} with {hash_algo}...")
                digest_to_check = compute_sha3_256(file_bytes) if hash_algo == "sha3_256" else compute_sha3_512(file_bytes)

                if digest_to_check.hex() != meta["hash"]:
                    self.verify_status.config(text="❌ HASH MISMATCH - FILE CORRUPTED!", bootstyle="danger")
                    self.log("Verification FAILED: The file's hash does not match the signed hash.")
                    return

                self.log("Loading certificate...")
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                try:
                    self.log("Verifying signature...")
                    if algo == "RSA":
                        cert.public_key().verify(
                            sig,
                            digest_to_check,
                            padding.PSS(
                                mgf=padding.MGF1(hashes.SHA3_256() if hash_algo == "sha3_256" else hashes.SHA3_512()),
                                salt_length=padding.PSS.MAX_LENGTH
                            ),
                            hashes.SHA3_256() if hash_algo == "sha3_256" else hashes.SHA3_512()
                        )
                    elif algo == "ECDSA":
                        cert.public_key().verify(sig, digest_to_check, ec.ECDSA(hashes.SHA3_256() if hash_algo == "sha3_256" else hashes.SHA3_512()))
                    else:
                        raise ValueError("Unsupported algorithm in certificate")
                    is_valid = True
                except Exception as e:
                    is_valid = False
                    self.log(f"Signature verification failed: {str(e)}")

                if not is_valid:
                    self.verify_status.config(text="❌ Signature INVALID", bootstyle="danger")
                    self.log("Verification FAILED: Signature is invalid.")
                    return

                # Check certificate validity period
                now = datetime.datetime.utcnow()
                if now > cert.not_valid_after:
                    self.verify_status.config(text="❌ Certificate Expired or Not Yet Valid", bootstyle="danger")
                    self.log("Verification FAILED: Certificate is not valid at current time.")
                    return

                self.verify_status.config(text=f"✅ Signature VALID (Signed by: {meta['signed_by']}) | Valid Until: {cert.not_valid_after.strftime('%Y-%m-%d %H:%M:%S')}", bootstyle="success")
                self.log("Verification SUCCESS: Signature is valid and certificate is within validity period.")

                # Display details in a more user-friendly way
                self.details_text.config(state=tk.NORMAL)
                self.details_text.insert(tk.END, "Certificate Details:\n\n")
                self.details_text.insert(tk.END, f"Subject: {cert.subject.rfc4514_string()}\n\n")
                self.details_text.insert(tk.END, f"Issuer: {cert.issuer.rfc4514_string()}\n\n")
                self.details_text.insert(tk.END, f"Serial Number: {cert.serial_number}\n\n")
                self.details_text.insert(tk.END, "Validity Period:\n")
                self.details_text.insert(tk.END, f"  From: {cert.not_valid_before.strftime('%Y-%m-%d %H:%M:%S')}\n")
                self.details_text.insert(tk.END, f"  To: {cert.not_valid_after.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                self.details_text.insert(tk.END, f"Signature Algorithm: {cert.signature_hash_algorithm.name}\n\n")
                self.details_text.insert(tk.END, "Extensions:\n")
                for ext in cert.extensions:
                    self.details_text.insert(tk.END, f"  - {ext.oid._name} (Critical: {ext.critical}): {ext.value}\n")
                self.details_text.insert(tk.END, f"\nSigned At: {meta.get('signed_at', 'N/A')}\n")
                self.details_text.config(state=tk.DISABLED)

        except Exception as e:
            self.log(f"ERROR during verification: {str(e)}")
            messagebox.showerror("Verification Error", str(e))

# main.py remains unchanged
