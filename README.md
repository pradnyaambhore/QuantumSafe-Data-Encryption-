# 🔐 QuantumSafe Data Encryption

### A Quantum-Resistant Secure File Encryption System

## 📌 Project Overview

QuantumSafe is a web-based secure file encryption and decryption system developed to explore Post-Quantum Cryptography (PQC).

The system combines post-quantum key encapsulation with authenticated encryption to protect sensitive files against emerging cybersecurity threats, including potential threats from quantum computing.

## 🎯 Project Objectives

- Implement secure file encryption and decryption.
- Explore Post-Quantum Cryptography.
- Protect encrypted data integrity.
- Provide secure cryptographic key management.
- Analyze encryption performance.
- Develop a user-friendly web-based security platform.

## 🚀 Key Features

- Secure File Encryption
- Secure File Decryption
- ML-KEM-768 Key Encapsulation
- AES-256-GCM Authenticated Encryption
- SHA3-256 Tamper Detection
- Security Analysis Dashboard
- Performance Benchmarking
- Cryptographic Inventory
- Key Management
- Audit Logging
- Security Test Lab
- QSF Encrypted File Format

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Python | Backend Development |
| Flask | Web Framework |
| HTML5 | Frontend Structure |
| CSS3 | User Interface |
| ML-KEM-768 | Post-Quantum Key Encapsulation |
| AES-256-GCM | Authenticated Encryption |
| SHA3-256 | Data Integrity |
| ML-DSA-65 | Post-Quantum Digital Signatures |

## 🏗️ System Architecture

1. User uploads a file through the web interface.
2. The system performs cryptographic key encapsulation.
3. A shared secret is derived for encryption.
4. AES-256-GCM encrypts the uploaded file.
5. The encrypted file is stored in QSF format.
6. The user can decrypt the encrypted file.
7. SHA3-256 is used to verify data integrity.

## 📂 Project Structure

```text
QuantumSafe/
│
├── app.py
├── crypto_core.py
├── app_backup.py
├── .gitignore
│
├── static/
│   └── style.css
│
├── templates/
│   ├── index.html
│   ├── audit_log.html
│   ├── benchmark.html
│   ├── crypto_inventory.html
│   ├── key_management.html
│   ├── security_analysis.html
│   └── security_test.html
│
├── README.md
│
└── uploads/
```

## ⚙️ Installation and Setup

### Step 1: Clone Repository

```bash
git clone https://github.com/pradnyaambhore/QuantumSafe-Data-Encryption-.git
```

### Step 2: Navigate to Project

```bash
cd QuantumSafe-Data-Encryption-
```

### Step 3: Install Dependencies

```bash
pip install flask cryptography
```

Install additional dependencies required by the cryptographic module.

### Step 4: Run Application

```bash
python app.py
```

### Step 5: Open in Browser

```text
http://127.0.0.1:5000
```

## 🔐 Cryptographic Algorithms

| Algorithm | Application |
|---|---|
| ML-KEM-768 | Secure Key Encapsulation |
| AES-256-GCM | File Encryption |
| SHA3-256 | Integrity Verification |
| ML-DSA-65 | Digital Signatures |

## 🔮 Future Scope

- Cloud-based secure file storage.
- Advanced cryptographic key management.
- Multi-user authentication.
- Enhanced security monitoring.
- Integration with additional post-quantum standards.

## 🎓 Project Information

**Project Name:** QuantumSafe Data Encryption

**Project Type:** Final Year Academic Project

**Domain:** Cybersecurity and Post-Quantum Cryptography

**Backend:** Python and Flask

**Frontend:** HTML and CSS

---

## 👩‍💻 Author

**Pradnya Ambhore**

GitHub: [Pradnya Ambhore](https://github.com/pradnyaambhore)

---

⭐ If you find this project interesting, consider giving the repository a star!