import io
import re
import zlib
import zipfile
import tempfile

from pathlib import Path

from PIL import Image

from flask import (
    Blueprint,
    render_template,
    request,
    jsonify,
)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


recovery_smb_bp = Blueprint(
    "recovery_smb",
    __name__
)

uploaded_zip_paths = []


# =========================================================
# LSB Extract
# =========================================================

def extract_lsb(image_path: Path) -> bytes:

    pixels = list(
        Image.open(image_path)
        .convert("RGB")
        .getdata()
    )

    bits = [
        str(ch & 1)
        for px in pixels
        for ch in px
    ]

    data_len = int(
        "".join(bits[:32]),
        2
    )

    data_bits = "".join(
        bits[32:32 + data_len]
    )

    return bytes(
        int(data_bits[i:i + 8], 2)
        for i in range(0, len(data_bits), 8)
        if len(data_bits[i:i + 8]) == 8
    )


# =========================================================
# AES-GCM Decrypt
# =========================================================

def decrypt_payload(
    encrypted_data: bytes,
    key_hex: str
) -> bytes:

    key_hex = key_hex.strip()

    try:

        key = bytes.fromhex(key_hex)

    except Exception:

        raise ValueError(
            "Recovery key is not valid HEX"
        )

    if len(key) not in (16, 24, 32):

        raise ValueError(
            "Invalid AES key length"
        )

    if len(encrypted_data) < 13:

        raise ValueError(
            "Encrypted payload too short"
        )

    nonce = encrypted_data[:12]

    ciphertext = encrypted_data[12:]

    aesgcm = AESGCM(key)

    return aesgcm.decrypt(
        nonce,
        ciphertext,
        None
    )


# =========================================================
# Hostname
# =========================================================

def extract_hostname(config: str) -> str:

    for line in config.splitlines():

        line = line.strip()

        if line.startswith("hostname "):

            hostname = line.split(
                "hostname ",
                1
            )[1].strip()

            hostname = re.sub(
                r'[^a-zA-Z0-9_.-]',
                '_',
                hostname
            )

            return hostname

    return "unknown-host"


# =========================================================
# VLAN1 IP
# =========================================================

def extract_vlan1_ip(config: str) -> str:

    lines = config.splitlines()

    inside_vlan1 = False

    for line in lines:

        stripped = line.strip()

        if stripped.lower().startswith(
            "interface vlan1"
        ):

            inside_vlan1 = True
            continue

        if inside_vlan1:

            if (
                stripped.startswith("interface ")
                and
                not stripped.lower().startswith(
                    "interface vlan1"
                )
            ):
                break

            match = re.search(
                r"ip address\s+(\d+\.\d+\.\d+\.\d+)",
                stripped,
                re.IGNORECASE
            )

            if match:

                return match.group(1)

    return "unknown-ip"


# =========================================================
# Recover ZIP
# =========================================================

def recover_zip(
    zip_path: Path,
    key_hex: str
):

    with tempfile.TemporaryDirectory() as tmp_dir:

        tmp_path = Path(tmp_dir)

        with zipfile.ZipFile(
            zip_path,
            "r"
        ) as zf:

            zf.extractall(tmp_path)

        pngs = sorted(
            tmp_path.rglob("img_*.png")
        )

        if not pngs:

            raise FileNotFoundError(
                "No PNG images found"
            )

        chunks = []

        index = 0

        while True:

            expected = f"img_{index:02d}.png"

            img = None

            for p in pngs:

                if p.name == expected:

                    img = p
                    break

            if not img:
                break

            chunks.append(
                extract_lsb(img)
            )

            index += 1

        if not chunks:

            raise Exception(
                "No image chunks found"
            )

        encrypted_data = b"".join(
            chunks
        )

        compressed_data = decrypt_payload(
            encrypted_data,
            key_hex
        )

        raw_data = zlib.decompress(
            compressed_data
        )

        config = raw_data.decode(
            "utf-8",
            errors="ignore"
        )

        hostname = extract_hostname(
            config
        )

        vlan1_ip = extract_vlan1_ip(
            config
        )

        filename = (
            f"{vlan1_ip}_{hostname}.txt"
        )

        return {
            "filename": filename,
            "config": config
        }


# =========================================================
# Page
# =========================================================

@recovery_smb_bp.route("/recovery")
def recovery_page():

    return render_template(
        "recoverysmb.html"
    )


# =========================================================
# Upload ZIPs
# =========================================================

@recovery_smb_bp.route(
    "/recovery/upload",
    methods=["POST"]
)
def recovery_upload():

    global uploaded_zip_paths

    try:

        uploaded_zip_paths = []

        files = request.files.getlist(
            "zip_files"
        )

        if not files:

            return jsonify({
                "success": False,
                "message": "No ZIP files uploaded"
            }), 400

        temp_dir = Path(
            tempfile.mkdtemp(
                prefix="smb_recovery_"
            )
        )

        uploaded_count = 0

        for file in files:

            if not file.filename:

                continue

            if not file.filename.lower().endswith(
                ".zip"
            ):

                continue

            filename = Path(
                file.filename
            ).name

            save_path = (
                temp_dir
                / filename
            )

            file.save(save_path)

            uploaded_zip_paths.append(
                save_path
            )

            uploaded_count += 1

        if uploaded_count == 0:

            return jsonify({
                "success": False,
                "message": "No valid ZIP files uploaded"
            }), 400

        return jsonify({
            "success": True,
            "count": uploaded_count
        })

    except Exception as e:

        print(
            "[RECOVERY_UPLOAD_ERROR]",
            str(e)
        )

        return jsonify({
            "success": False,
            "message": str(e)
        }), 500


# =========================================================
# Decode
# =========================================================

@recovery_smb_bp.route(
    "/recovery/decode",
    methods=["POST"]
)
def recovery_decode():

    try:

        key_hex = request.form.get(
            "recovery_key",
            ""
        ).strip()

        if not key_hex:

            return jsonify({
                "success": False,
                "message": "Recovery key required"
            }), 400

        if not uploaded_zip_paths:

            return jsonify({
                "success": False,
                "message": "No uploaded ZIP files found"
            }), 400

        results = []

        for zip_path in uploaded_zip_paths:

            try:

                result = recover_zip(
                    zip_path,
                    key_hex
                )

                results.append({
                    "success": True,
                    "filename": result["filename"],
                    "content": result["config"]
                })

            except Exception as e:

                results.append({
                    "success": False,
                    "zip": zip_path.name,
                    "error": str(e)
                })

        return jsonify(results)

    except Exception as e:

        print(
            "[RECOVERY_DECODE_ERROR]",
            str(e)
        )

        return jsonify({
            "success": False,
            "message": str(e)
        }), 500
