# 🔐 CodeSigner: A Python-based Code Signing Tool

This repository contains a **simple, yet functional, code signing and verification tool** built with Python. It allows users to **generate self-signed certificates, digitally sign files, and verify the integrity and authenticity of signed packages**.  
The tool provides a **user-friendly graphical interface** using **ttkbootstrap**.

---

## 🌟 Features

- **Key Management**  
  - Generate and load **RSA** and **ECDSA** private keys.  
  - Keys can be **password-protected** and saved in **PEM** format.

- **Self-Signed Certificates**  
  - Create a **self-signed X.509 certificate** with a configurable validity period and signer details.

- **Digital Signing**  
  - Sign any file using **SHA3-256** or **SHA3-512** hashing algorithms.  
  - The process bundles the **original file, signature, and certificate** into a single **ZIP package** for easy distribution.

- **Verification**  
  - Verify the **integrity and authenticity** of a signed **ZIP package**.  
  - The tool:
    - Checks the file's **hash** against the signed hash.
    - Validates the **digital signature**.
    - Confirms the **certificate's validity period**.

- **GUI**  
  - A **clean and intuitive graphical user interface** makes the tool accessible even to users without deep command-line knowledge.

---

## 💻 Prerequisites

- **Python 3.6+**
- Install the required Python libraries using:

```bash
pip install -r requirements.txt
````

---

## 🛠️ Installation

Clone the repository:

```bash
git clone https://github.com/your-username/CodeSigner.git
cd CodeSigner
```

Install the dependencies:

```bash
pip install -r requirements.txt
```

---

## 🚀 Usage

Run the application:

```bash
python main.py
```

---

### **Key Management Tab** (🔑 **Key Management**)

* **Load Existing Key**
  Load an existing private key (`.pem` file).
  If the key is **encrypted**, the tool will prompt for a **password**.
* **Generate New Key**

  * Choose between **RSA** or **ECDSA**.
  * Fill in the **signer details** (e.g., Common Name, Organization).
  * Click **Generate Key**.
  * Set a **password** for the new key.
  * The private key and a **companion JSON file** with signer details will be saved.

---

### **Sign File Tab** (✍️ **Sign File**)

* **Choose File** → Select the file to sign.
* **Select Hash Algorithm** → Choose between **SHA3-256** and **SHA3-512**.
* **Sign & Create ZIP** →
  Creates a **signed package** (`.zip`) containing:

  * The **original file**
  * The **digital signature**
  * A **self-signed certificate**
  * **Metadata**

---

### **Verify Package Tab** (🕵️ **Verify Package**)

* **Choose ZIP** → Select the signed `.zip` package to verify.
* **Verify** → The tool performs:

  1. **Hash validation** → Does the file hash match the signed hash?
  2. **Signature verification** → Is the **digital signature valid**?
  3. **Certificate check** → Is the **embedded certificate valid**?

The **verification status** and **detailed certificate information** will be displayed in the interface.

---

## 📂 Project Structure

```
.
├── certificate.py      # Handles X.509 self-signed certificate creation
├── gui_app.py          # Main GUI app class (CodeSignerApp)
├── hashing.py          # Contains SHA3 hashing logic
├── main.py             # Entry point of the application
├── requirements.txt    # Required Python dependencies
└── signing.py          # Key generation, signing & verification logic
```

---

## 🤝 Contributing

Contributions are welcome! 🎉
If you find a bug or have a suggestion, please **open an issue** or **submit a pull request**.

---

## 📜 License

This project is licensed under the **MIT License**.
See the [LICENSE](LICENSE) file for more details.

```

---

### How to Save It:
1. Create a file named **`README.md`** in the root directory of the project.
2. Paste the above code.
3. Save the file.

---

If you want, I can also make it **more visually appealing** by adding badges, screenshots, and better formatting to give it a **professional GitHub look**.  

Do you want me to upgrade it into a **pro-level README**?
```

