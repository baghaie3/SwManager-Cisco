from pathlib import Path
from PIL import Image
import random
import secrets
from datetime import datetime
import zlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DATASET_DIR = Path("Dataset")
STEGO_DIR   = Path("StegoStorage")
NUM_IMAGES  = 2


# ==================== Crypto Helpers ====================

def _get_backup_key() -> bytes:
    key_hex = os.environ.get("STEGO_BACKUP_KEY_HEX")
    if not key_hex:
        raise RuntimeError("STEGO_BACKUP_KEY_HEX is not set")

    try:
        key = bytes.fromhex(key_hex)
    except ValueError as e:
        raise RuntimeError("STEGO_BACKUP_KEY_HEX must be valid hex") from e

    if len(key) not in (16, 24, 32):
        raise RuntimeError(
            "STEGO_BACKUP_KEY_HEX must decode to 16, 24, or 32 bytes "
            "(recommended: 32 bytes for AES-256)"
        )

    return key


def _encrypt(data: bytes) -> bytes:
    key = _get_backup_key()
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext


def _decrypt(data: bytes) -> bytes:
    if len(data) < 13:
        raise ValueError("Encrypted payload too short")

    key = _get_backup_key()
    aesgcm = AESGCM(key)
    nonce = data[:12]
    ciphertext = data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)


# ==================== Helpers ====================

def get_random_images(count: int = NUM_IMAGES) -> list[Path]:
    images = (
        list(DATASET_DIR.glob("*.jpg"))
        + list(DATASET_DIR.glob("*.jpeg"))
        + list(DATASET_DIR.glob("*.png"))
    )
    if len(images) < count:
        raise ValueError(f"Dataset has {len(images)} images, need {count}")
    return random.sample(images, count)


def split_data(data: bytes, chunks: int = NUM_IMAGES) -> list[bytes]:
    size = len(data)
    base, rem = divmod(size, chunks)
    parts, offset = [], 0
    for i in range(chunks):
        n = base + (1 if i < rem else 0)
        parts.append(data[offset : offset + n])
        offset += n
    return parts


# ==================== Encoder ====================

def _embed(image_path: Path, data: bytes, output_path: Path) -> None:
    img = Image.open(image_path).convert("RGB")
    pixels = list(img.getdata())

    data_bits = "".join(format(b, "08b") for b in data)
    all_bits = format(len(data_bits), "032b") + data_bits

    if len(all_bits) > len(pixels) * 3:
        raise ValueError(
            f"Image {image_path.name} too small "
            f"({len(pixels) * 3} bits available, need {len(all_bits)})"
        )

    new_pixels, bit_idx = [], 0
    for r, g, b in pixels:
        if bit_idx < len(all_bits):
            r = (r & 0xFE) | int(all_bits[bit_idx])
            bit_idx += 1
        if bit_idx < len(all_bits):
            g = (g & 0xFE) | int(all_bits[bit_idx])
            bit_idx += 1
        if bit_idx < len(all_bits):
            b = (b & 0xFE) | int(all_bits[bit_idx])
            bit_idx += 1
        new_pixels.append((r, g, b))

    out = Image.new("RGB", img.size)
    out.putdata(new_pixels)
    out.save(output_path, "PNG")


def encode_backup_to_images(
    config_text: str,
    switch_name: str,
    switch_ip: str,
    timestamp: str,
    switch_id: int,
) -> str:
    # 1) utf-8
    raw_data = config_text.encode("utf-8")

    # 2) compress
    compressed_data = zlib.compress(raw_data, level=9)

    # 3) encrypt
    encrypted_data = _encrypt(compressed_data)

    chunks = split_data(encrypted_data, NUM_IMAGES)
    img_paths = get_random_images(NUM_IMAGES)

    backup_id = secrets.token_hex(16).upper()

    now = datetime.now()
    year = now.strftime("%Y")
    month = now.strftime("%m")

    out_dir = STEGO_DIR / year / month / backup_id
    out_dir.mkdir(parents=True, exist_ok=True)

    for i, (chunk, src) in enumerate(zip(chunks, img_paths)):
        dst = out_dir / f"img_{i:02d}.png"
        _embed(src, chunk, dst)

    from models import Backup, db

    backup_record = Backup(
        backup_id=backup_id,
        switch_id=switch_id,
        created_at=now,
        year=year,
        month=month
    )
    db.session.add(backup_record)
    db.session.commit()

    return backup_id


# ==================== Decoder ====================

def _extract(image_path: Path) -> bytes:
    pixels = list(Image.open(image_path).convert("RGB").getdata())
    bits = [str(ch & 1) for px in pixels for ch in px]

    data_len = int("".join(bits[:32]), 2)
    data_bits = "".join(bits[32 : 32 + data_len])

    return bytes(
        int(data_bits[i : i + 8], 2)
        for i in range(0, len(data_bits), 8)
        if len(data_bits[i : i + 8]) == 8
    )


def decode_backup_from_images(backup_id: str) -> str:
    for year_dir in STEGO_DIR.iterdir():
        if not year_dir.is_dir():
            continue

        for month_dir in year_dir.iterdir():
            if not month_dir.is_dir():
                continue

            backup_dir = month_dir / backup_id
            if backup_dir.exists() and backup_dir.is_dir():
                chunks = []

                for i in range(NUM_IMAGES):
                    img_path = backup_dir / f"img_{i:02d}.png"
                    if not img_path.exists():
                        raise FileNotFoundError(f"Missing image: {img_path}")
                    chunks.append(_extract(img_path))

                encrypted_data = b"".join(chunks)

                # 1) decrypt
                compressed_data = _decrypt(encrypted_data)

                # 2) decompress
                raw_data = zlib.decompress(compressed_data)

                return raw_data.decode("utf-8")

    raise FileNotFoundError(f"Backup {backup_id} not found in {STEGO_DIR}")
