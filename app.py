from flask import Flask, render_template, request, send_file

from crypto_core import (
    encrypt_data,
    decrypt_data,
    verify_hash,
    generate_signature_keys,
    sign_data,
    verify_signature
)

import os
import json
import base64
import time

from datetime import datetime


app = Flask(__name__)

UPLOAD_FOLDER = "uploads"

os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)


# ============================================================
# AUDIT LOG
# ============================================================

AUDIT_LOG_FILE = "audit_log.json"


def add_audit_log(event, status, details):

    log_entry = {
        "timestamp": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "event": event,
        "status": status,
        "details": details
    }

    logs = []

    if os.path.exists(AUDIT_LOG_FILE):

        try:

            with open(
                AUDIT_LOG_FILE,
                "r"
            ) as f:

                logs = json.load(f)

        except Exception:

            logs = []

    logs.append(log_entry)

    with open(
        AUDIT_LOG_FILE,
        "w"
    ) as f:

        json.dump(
            logs,
            f,
            indent=4
        )


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


# ============================================================
# AUDIT LOG
# ============================================================

@app.route("/audit-log")
def audit_log():

    logs = []

    if os.path.exists(AUDIT_LOG_FILE):

        try:

            with open(
                AUDIT_LOG_FILE,
                "r"
            ) as f:

                logs = json.load(f)

        except Exception:

            logs = []

    return render_template(
        "audit_log.html",
        logs=logs
    )


# ============================================================
# CRYPTO INVENTORY
# ============================================================

@app.route("/crypto-inventory")
def crypto_inventory():

    return render_template(
        "crypto_inventory.html"
    )


# ============================================================
# KEY MANAGEMENT
# ============================================================

@app.route("/key-management")
def key_management():

    return render_template(
        "key_management.html"
    )


# ============================================================
# SECURITY ANALYSIS
# ============================================================

@app.route("/security-analysis")
def security_analysis():

    return render_template(
        "security_analysis.html"
    )


# ============================================================
# ENCRYPT FILE
# ============================================================

@app.route(
    "/encrypt",
    methods=["POST"]
)
def encrypt_file():

    if "file" not in request.files:

        return "No file selected"

    file = request.files["file"]

    if file.filename == "":

        return "No file selected"

    try:

        data = file.read()

        encrypted = encrypt_data(
            data
        )

        encrypted_data = encrypted[
            "encrypted_data"
        ]


        # ----------------------------------------------------
        # ML-DSA-65 DIGITAL SIGNATURE
        # ----------------------------------------------------

        signature_public_key, signature_secret_key = (
            generate_signature_keys()
        )

        signature = sign_data(
            encrypted_data,
            signature_secret_key
        )


        # ----------------------------------------------------
        # QSF PACKAGE
        # ----------------------------------------------------

        package = {

            "algorithm":
                "ML-KEM-768 + HKDF + AES-256-GCM",

            "integrity":
                "SHA3-256",

            "digital_signature":
                "ML-DSA-65",

            "original_filename":
                file.filename,

            "kem_ciphertext":
                base64.b64encode(
                    encrypted["kem_ciphertext"]
                ).decode(),

            "nonce":
                base64.b64encode(
                    encrypted["nonce"]
                ).decode(),

            "encrypted_data":
                base64.b64encode(
                    encrypted_data
                ).decode(),

            "secret_key":
                base64.b64encode(
                    encrypted["secret_key"]
                ).decode(),

            "data_hash":
                encrypted["data_hash"],

            "signature_public_key":
                base64.b64encode(
                    signature_public_key
                ).decode(),

            "signature":
                base64.b64encode(
                    signature
                ).decode()
        }


        output_path = os.path.join(
            UPLOAD_FOLDER,
            file.filename + ".qsf"
        )


        with open(
            output_path,
            "w"
        ) as f:

            json.dump(
                package,
                f,
                indent=4
            )


        add_audit_log(
            "File Encryption",
            "SUCCESS",
            f"Encrypted file: {file.filename}"
        )


        return send_file(
            output_path,
            as_attachment=True,
            download_name=file.filename + ".qsf"
        )


    except Exception as e:

        add_audit_log(
            "File Encryption",
            "FAILED",
            str(e)
        )

        return "Encryption failed"


# ============================================================
# SECURITY TEST
# ============================================================

@app.route(
    "/security-test",
    methods=["POST"]
)
def security_test():

    if "file" not in request.files:

        return "No file selected"

    file = request.files["file"]

    if file.filename == "":

        return "No file selected"

    try:

        package = json.loads(
            file.read().decode(
                "utf-8"
            )
        )


        encrypted_data = base64.b64decode(
            package["encrypted_data"]
        )

        expected_hash = package[
            "data_hash"
        ]


        integrity_ok = verify_hash(
            encrypted_data,
            expected_hash
        )


        if integrity_ok:

            add_audit_log(
                "Security Test",
                "PASSED",
                "SHA3-256 integrity verification successful"
            )


            return """
            <html>

            <head>

                <title>
                    Security Test
                </title>

            </head>

            <body>

                <h1>
                    SECURITY TEST PASSED
                </h1>

                <h2>
                    SHA3-256 Integrity Verification
                </h2>

                <p>
                    No modification was detected
                    in the encrypted data.
                </p>

                <p>
                    Integrity Status:
                    <strong>VALID</strong>
                </p>

                <br>

                <a href="/">
                    Back to Dashboard
                </a>

            </body>

            </html>
            """


        else:

            add_audit_log(
                "Security Test",
                "TAMPER DETECTED",
                "SHA3-256 integrity verification failed"
            )


            return """
            <html>

            <head>

                <title>
                    Security Test
                </title>

            </head>

            <body>

                <h1>
                    TAMPER DETECTED
                </h1>

                <h2>
                    SHA3-256 Integrity Verification Failed
                </h2>

                <p>
                    The encrypted data appears
                    to have been modified.
                </p>

                <p>
                    Integrity Status:
                    <strong>INVALID</strong>
                </p>

                <br>

                <a href="/">
                    Back to Dashboard
                </a>

            </body>

            </html>
            """


    except Exception as e:

        add_audit_log(
            "Security Test",
            "FAILED",
            str(e)
        )


        return """
        <h1>
            SECURITY TEST FAILED
        </h1>

        <p>
            The uploaded QSF file is invalid
            or corrupted.
        </p>

        <a href="/">
            Back to Dashboard
        </a>
        """


# ============================================================
# PERFORMANCE BENCHMARK
# ============================================================

@app.route(
    "/benchmark",
    methods=["POST"]
)
def benchmark():

    if "file" not in request.files:

        return "No file selected"

    file = request.files["file"]

    if file.filename == "":

        return "No file selected"

    try:

        data = file.read()

        file_size = len(data)


        # ----------------------------------------------------
        # ENCRYPTION
        # ----------------------------------------------------

        encryption_start = time.perf_counter()

        encrypted = encrypt_data(
            data
        )

        encryption_end = time.perf_counter()

        encryption_time = (
            encryption_end -
            encryption_start
        )


        # ----------------------------------------------------
        # ML-DSA SIGNATURE
        # ----------------------------------------------------

        signature_start = time.perf_counter()

        public_key, secret_key = (
            generate_signature_keys()
        )

        signature = sign_data(
            encrypted["encrypted_data"],
            secret_key
        )

        signature_end = time.perf_counter()

        signature_time = (
            signature_end -
            signature_start
        )


        # ----------------------------------------------------
        # DECRYPTION
        # ----------------------------------------------------

        decryption_start = time.perf_counter()

        decrypted = decrypt_data(

            encrypted["kem_ciphertext"],

            encrypted["nonce"],

            encrypted["encrypted_data"],

            encrypted["secret_key"]
        )

        decryption_end = time.perf_counter()

        decryption_time = (
            decryption_end -
            decryption_start
        )


        # ----------------------------------------------------
        # SIGNATURE VERIFICATION
        # ----------------------------------------------------

        verification_start = time.perf_counter()

        signature_valid = verify_signature(

            encrypted["encrypted_data"],

            signature,

            public_key
        )

        verification_end = time.perf_counter()

        verification_time = (
            verification_end -
            verification_start
        )


        if signature_valid:

            verification_status = "VALID"

        else:

            verification_status = "INVALID"


        add_audit_log(
            "Performance Benchmark",
            "COMPLETED",
            f"File size: {file_size} bytes"
        )


        return f"""
        <html>

        <head>

            <title>
                Performance Benchmark
            </title>

        </head>

        <body>

            <h1>
                Performance Benchmark Result
            </h1>

            <hr>

            <h2>
                File Information
            </h2>

            <p>
                File Size:
                <strong>
                    {file_size} bytes
                </strong>
            </p>

            <hr>

            <h2>
                Encryption Performance
            </h2>

            <p>
                ML-KEM-768 + AES-256-GCM:
                <strong>
                    {encryption_time:.6f} seconds
                </strong>
            </p>

            <hr>

            <h2>
                ML-DSA-65 Performance
            </h2>

            <p>
                Signature Generation:
                <strong>
                    {signature_time:.6f} seconds
                </strong>
            </p>

            <p>
                Signature Verification:
                <strong>
                    {verification_time:.6f} seconds
                </strong>
            </p>

            <p>
                Verification Status:
                <strong>
                    {verification_status}
                </strong>
            </p>

            <hr>

            <h2>
                Decryption Performance
            </h2>

            <p>
                ML-KEM-768 + AES-256-GCM:
                <strong>
                    {decryption_time:.6f} seconds
                </strong>
            </p>

            <hr>

            <h2>
                Algorithms Tested
            </h2>

            <ul>

                <li>ML-KEM-768</li>

                <li>HKDF-SHA3-256</li>

                <li>AES-256-GCM</li>

                <li>SHA3-256</li>

                <li>ML-DSA-65</li>

            </ul>

            <br>

            <a href="/">
                Back to Dashboard
            </a>

        </body>

        </html>
        """


    except Exception as e:

        add_audit_log(
            "Performance Benchmark",
            "FAILED",
            str(e)
        )


        return f"""
        <h1>
            Benchmark Failed
        </h1>

        <p>
            {str(e)}
        </p>

        <a href="/">
            Back to Dashboard
        </a>
        """


# ============================================================
# DECRYPT FILE
# ============================================================

@app.route(
    "/decrypt",
    methods=["POST"]
)
def decrypt_file():

    if "file" not in request.files:

        return "No file selected"

    file = request.files["file"]

    if file.filename == "":

        return "No file selected"

    try:

        package = json.loads(
            file.read().decode(
                "utf-8"
            )
        )


        encrypted_data = base64.b64decode(
            package["encrypted_data"]
        )


        # ----------------------------------------------------
        # SHA3-256 INTEGRITY CHECK
        # ----------------------------------------------------

        expected_hash = package[
            "data_hash"
        ]

        integrity_ok = verify_hash(
            encrypted_data,
            expected_hash
        )


        if not integrity_ok:

            add_audit_log(
                "File Decryption",
                "BLOCKED",
                "SHA3-256 tamper detection triggered"
            )


            return """
            <h1>
                TAMPER DETECTED
            </h1>

            <p>
                The encrypted file has been modified
                or corrupted.
            </p>

            <p>
                SHA3-256 integrity verification failed.
            </p>

            <p>
                Decryption has been blocked for security.
            </p>
            """


        # ----------------------------------------------------
        # ML-DSA-65 SIGNATURE VERIFICATION
        # ----------------------------------------------------

        signature_public_key = base64.b64decode(
            package["signature_public_key"]
        )

        signature = base64.b64decode(
            package["signature"]
        )


        signature_valid = verify_signature(

            encrypted_data,

            signature,

            signature_public_key
        )


        if not signature_valid:

            add_audit_log(
                "Digital Signature Verification",
                "FAILED",
                "ML-DSA-65 signature verification failed"
            )


            return """
            <h1>
                DIGITAL SIGNATURE INVALID
            </h1>

            <p>
                ML-DSA-65 signature verification failed.
            </p>

            <p>
                Decryption has been blocked for security.
            </p>
            """


        add_audit_log(
            "Digital Signature Verification",
            "PASSED",
            "ML-DSA-65 signature verified successfully"
        )


        # ----------------------------------------------------
        # ML-KEM DATA
        # ----------------------------------------------------

        kem_ciphertext = base64.b64decode(
            package["kem_ciphertext"]
        )

        nonce = base64.b64decode(
            package["nonce"]
        )

        secret_key = base64.b64decode(
            package["secret_key"]
        )


        # ----------------------------------------------------
        # DECRYPT
        # ----------------------------------------------------

        decrypted_data = decrypt_data(

            kem_ciphertext,

            nonce,

            encrypted_data,

            secret_key
        )


        # ----------------------------------------------------
        # SAVE DECRYPTED FILE
        # ----------------------------------------------------

        original_filename = package[
            "original_filename"
        ]


        output_path = os.path.join(

            UPLOAD_FOLDER,

            "decrypted_" +
            original_filename
        )


        with open(
            output_path,
            "wb"
        ) as f:

            f.write(
                decrypted_data
            )


        add_audit_log(
            "File Decryption",
            "SUCCESS",
            f"Decrypted file: {original_filename}"
        )


        return send_file(

            output_path,

            as_attachment=True,

            download_name=original_filename
        )


    except Exception as e:

        add_audit_log(
            "File Decryption",
            "FAILED",
            str(e)
        )


        return """
        <h1>
            Decryption Failed
        </h1>

        <p>
            The QSF file is invalid, corrupted,
            or cannot be decrypted.
        </p>

        <a href="/">
            Back to Dashboard
        </a>
        """


# ============================================================
# RUN SERVER
# ============================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )