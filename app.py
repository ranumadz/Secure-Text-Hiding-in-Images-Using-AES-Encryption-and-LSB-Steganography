# app.py
"""
Streamlit app: AES (password-based) + LSB steganography (image).
- Embeds AES-encrypted message into an image's pixel LSBs.
- For safety with JPG (lossy), the app converts uploaded images to PNG (lossless)
  before embedding and produces a PNG stego-image for download.
- Uses AES-128-CBC with PKCS7 padding and PBKDF2-HMAC-SHA256 for password->key.
"""

import streamlit as st
from PIL import Image
import numpy as np
import io
import base64
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

# ---------------------------
# Config / Styling
# ---------------------------
st.set_page_config(page_title="StegoVault — AES + LSB", layout="wide",
                   initial_sidebar_state="expanded",
                   page_icon="🔐")

# Simple CSS to polish look
st.markdown("""
<style>
.header {
  display:flex;
  align-items:center;
  gap:16px;
}
.app-title {
  font-size:28px;
  font-weight:700;
}
.card {
  background: #ffffff;
  padding: 14px;
  border-radius: 10px;
  box-shadow: 0 2px 6px rgba(0,0,0,0.06);
}
.small-muted { color: #6c757d; font-size:13px; }
.stat { font-weight:700; font-size:18px; }
pre.codebox { background:#f8f9fa; padding:12px; border-radius:8px; }
</style>
""", unsafe_allow_html=True)

# ---------------------------
# Crypto helpers
# ---------------------------
SALT_BYTES = 16
PBKDF2_ITERS = 200_000  # strong enough for interactive use
KEY_LEN = 16  # AES-128

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive AES key from password and salt using PBKDF2-HMAC-SHA256."""
    return PBKDF2(password.encode('utf-8'), salt, dkLen=KEY_LEN, count=PBKDF2_ITERS, hmac_hash_module=None)

def pkcs7_pad(data: bytes, block_size=16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding")
    return data[:-pad_len]

def aes_encrypt(plaintext: bytes, password: str) -> bytes:
    """Return: salt || iv || ciphertext (raw bytes)."""
    salt = get_random_bytes(SALT_BYTES)
    key = derive_key(password, salt)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pkcs7_pad(plaintext))
    return salt + iv + ct

def aes_decrypt(blob: bytes, password: str) -> bytes:
    """Input blob = salt||iv||ciphertext"""
    if len(blob) < SALT_BYTES + 16:
        raise ValueError("Ciphertext too short")
    salt = blob[:SALT_BYTES]
    iv = blob[SALT_BYTES:SALT_BYTES+16]
    ct = blob[SALT_BYTES+16:]
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt_padded = cipher.decrypt(ct)
    return pkcs7_unpad(pt_padded)

# ---------------------------
# LSB steganography helpers
# ---------------------------
def img_to_rgb_array(image: Image.Image) -> np.ndarray:
    return np.array(image.convert("RGB"), dtype=np.uint8)

def rgb_array_to_image(arr: np.ndarray) -> Image.Image:
    return Image.fromarray(arr.astype(np.uint8), 'RGB')

def max_capacity_bytes(img_arr: np.ndarray) -> int:
    h, w, c = img_arr.shape
    # we use 1 LSB per channel -> 3 bits per pixel -> capacity in bytes
    return (h * w * c) // 8  # integer bytes

def embed_bytes_into_image(img_arr: np.ndarray, data_bytes: bytes) -> np.ndarray:
    """
    Embed data_bytes into image LSBs.
    Format embedded: 32-bit big-endian length (bytes) + data_bytes
    """
    h, w, c = img_arr.shape
    flat = img_arr.flatten()
    total_bits = flat.size  # total number of LSB positions
    header = len(data_bytes).to_bytes(4, 'big')
    payload = header + data_bytes
    needed_bits = len(payload) * 8
    if needed_bits > total_bits:
        raise ValueError(f"Data too large to embed. Need {needed_bits} bits, have {total_bits} bits.")
    # convert payload to bits
    bitstream = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))
    # clear LSBs and set
    flat_cleared = (flat & 0xFE).astype(np.uint8)
    flat_embedded = flat_cleared.copy()
    # set LSBs to bitstream
    flat_embedded[:len(bitstream)] |= bitstream
    # reshape back
    arr_emb = flat_embedded.reshape(img_arr.shape)
    return arr_emb

def extract_bytes_from_image(img_arr: np.ndarray) -> bytes:
    flat = img_arr.flatten()
    bits = flat & 1
    # read first 32 bits to get length
    if bits.size < 32:
        raise ValueError("Image too small")
    header_bits = bits[:32]
    header_bytes = np.packbits(header_bits)
    length = int.from_bytes(header_bytes.tobytes(), 'big')
    total_payload_bits = (4 + length) * 8
    if total_payload_bits > bits.size:
        raise ValueError("Declared payload length exceeds image capacity or image corrupted.")
    payload_bits = bits[:total_payload_bits]
    payload_bytes = np.packbits(payload_bits)
    return payload_bytes.tobytes()[4:]  # skip header

# ---------------------------
# Utility: image IO helpers
# ---------------------------
def pil_image_to_bytes(img: Image.Image, fmt='PNG') -> bytes:
    b = io.BytesIO()
    img.save(b, format=fmt)
    return b.getvalue()

def bytes_to_pil_image(b: bytes) -> Image.Image:
    return Image.open(io.BytesIO(b))

# ---------------------------
# UI: Sidebar and navigation
# ---------------------------
st.sidebar.title("StegoVault")
st.sidebar.caption("AES + LSB")
mode = st.sidebar.radio("Mode", ["Enkripsi (Embed)", "Dekripsi (Extract)", "Dashboard", "Tentang"])

# small helper to show capacity & notes
def show_image_info(img: Image.Image):
    arr = img_to_rgb_array(img)
    cap = max_capacity_bytes(arr)
    st.markdown(f"**Resolusi:** {img.width} × {img.height} px • **Kapasitas (max data):** **{cap} bytes** (≈ {cap/1024:.2f} KB)")
    st.markdown("> **Catatan:** untuk keamanan embedding yang andal, hasil akhir disimpan dalam format PNG (lossless). Jika Anda upload JPG, app akan mengonversi ke PNG sebelum embedding.")

# ---------------------------
# Mode: Enkripsi / Embed
# ---------------------------
if mode == "Enkripsi (Embed)":
    st.markdown('<div class="header"><div class="app-title"> Enkripsi & Sisipkan — AES + LSB</div></div>', unsafe_allow_html=True)
    c1, c2 = st.columns([2,1])
    with c1:
        st.markdown("### 1) Upload gambar (cover)")
        uploaded = st.file_uploader("Pilih gambar (JPG/PNG). Bila JPG akan dikonversi ke PNG sebelum embedding.", type=['png','jpg','jpeg'])
        if uploaded is not None:
            img = Image.open(uploaded)
            st.image(img, caption="Cover image (preview)", use_column_width=True)
            show_image_info(img)
        else:
            st.info("Unggah gambar untuk melanjutkan.")
    with c2:
        st.markdown("### 2) Pesan & Kunci")
        plaintext = st.text_area("Pesan teks yang ingin disembunyikan", height=180)
        password = st.text_input("Password (untuk AES)", type="password")
        pw_gen = st.button("🔑 Generate random password (16 chars)")
        if pw_gen:
            password = base64.urlsafe_b64encode(get_random_bytes(12)).decode()[:16]
            st.experimental_set_query_params()  # no-op to refresh small
            st.success("Password di-generate — salin segera!")
            st.write(password)
        st.markdown("**Advanced:** pilih mode enkripsi (AES-128-CBC dengan PBKDF2).")
        embed_btn = st.button("▶️ Enkripsi & Sisipkan ke gambar")
    # perform embedding when clicked
    if uploaded is not None and embed_btn:
        if plaintext.strip() == "":
            st.error("Pesan kosong — masukkan pesan yang akan disisipkan.")
        elif password.strip() == "":
            st.error("Masukkan password untuk AES.")
        else:
            try:
                with st.spinner("Mempersiapkan..."):
                    # ensure lossless: convert to RGB and treat it as PNG internals
                    cover_img = img.convert("RGB")
                    arr = img_to_rgb_array(cover_img)
                    # encrypt
                    encrypted_blob = aes_encrypt(plaintext.encode('utf-8'), password)
                    # embed
                    cap = max_capacity_bytes(arr)
                    if len(encrypted_blob) > cap:
                        st.error(f"Data terenkripsi ({len(encrypted_blob)} bytes) melebihi kapasitas gambar ({cap} bytes). Coba gunakan gambar resolusi lebih besar atau kurangi pesan.")
                    else:
                        arr_emb = embed_bytes_into_image(arr, encrypted_blob)
                        stego_img = rgb_array_to_image(arr_emb)
                        out_bytes = pil_image_to_bytes(stego_img, fmt='PNG')
                        st.success("Berhasil menyisipkan pesan! Hasil disimpan sebagai PNG (lossless).")
                        st.image(stego_img, caption="Stego image (preview)", use_column_width=True)
                        st.download_button("⬇️ Unduh gambar hasil (PNG)", data=out_bytes, file_name="stego_image.png", mime="image/png")
                        # show small hex preview of encrypted blob
                        st.markdown("**Preview (metadata)**")
                        st.code(f"Encrypted payload size: {len(encrypted_blob)} bytes\nHeader (salt+iv) len: {SALT_BYTES}+16\nFirst 32 bytes (hex): {encrypted_blob[:32].hex()}")
            except Exception as e:
                st.exception(e)

# ---------------------------
# Mode: Dekripsi / Extract
# ---------------------------
elif mode == "Dekripsi (Extract)":
    st.markdown('<div class="header"><div class="app-title">🔓 Ekstraksi & Dekripsi</div></div>', unsafe_allow_html=True)
    col1, col2 = st.columns([2,1])
    with col1:
        uploaded_stego = st.file_uploader("Upload gambar stego (PNG recommended)", type=['png','jpg','jpeg'])
        if uploaded_stego is not None:
            img_s = Image.open(uploaded_stego)
            st.image(img_s, caption="Stego image (preview)", use_column_width=True)
            show_image_info(img_s)
    with col2:
        st.markdown("### Input password untuk dekripsi")
        password_d = st.text_input("Password (sama seperti saat enkripsi)", type="password")
        extract_btn = st.button("🔍 Ekstrak & Dekripsi")
    if uploaded_stego is not None and extract_btn:
        if password_d.strip() == "":
            st.error("Masukkan password.")
        else:
            try:
                arr_s = img_to_rgb_array(img_s.convert("RGB"))
                extracted = extract_bytes_from_image(arr_s)
                # attempt decrypt
                try:
                    pt = aes_decrypt(extracted, password_d)
                    st.success("Dekripsi berhasil! Pesan:")
                    st.code(pt.decode('utf-8'))
                except Exception as e:
                    st.error("Gagal mendekripsi: password salah atau data rusak.")
                    st.exception(e)
            except Exception as e:
                st.exception(e)

# ---------------------------
# Mode: Dashboard
# ---------------------------
elif mode == "Dashboard":
    st.markdown('<div class="header"><div class="app-title">📊 Dashboard & Tools</div></div>', unsafe_allow_html=True)
    st.write("Ringkasan fitur dan alat bantu untuk pengujian / debugging.")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("#### 🧪 Sample test")
        sample_msg = st.text_area("Contoh pesan (untuk uji cepat)", value="Halo, ini pesan uji!", height=120)
        sample_pw = st.text_input("Password uji (sample)", value="testpassword", key="pw_sample")
        if st.button("Generate sample stego image (2MB-ish)", key="gen_sample"):
            # create synthetic image 400x300
            img = Image.new('RGB', (400,300), color=(123,200,150))
            arr = img_to_rgb_array(img)
            enc = aes_encrypt(sample_msg.encode('utf-8'), sample_pw)
            try:
                arr_emb = embed_bytes_into_image(arr, enc)
                stego_img = rgb_array_to_image(arr_emb)
                st.image(stego_img, caption="Sample stego (preview)")
                st.download_button("Unduh sample stego (PNG)", data=pil_image_to_bytes(stego_img, 'PNG'), file_name="sample_stego.png", mime="image/png")
            except Exception as e:
                st.error("Gagal membuat sample: " + str(e))
    with col2:
        st.markdown("#### ℹ️ Info teknis")
        st.markdown(f"- AES mode: AES-128-CBC\n- Key derivation: PBKDF2-HMAC-SHA256 ({PBKDF2_ITERS} iterations)\n- Salt length: {SALT_BYTES} bytes\n- Storage format embedded: `[4-byte length][salt(16)][iv(16)][ciphertext]` embedded as raw bytes into image LSBs.")
    with col3:
        st.markdown("#### ⚠️ Performa / kapasitas")
        st.markdown("Contoh kapasitas (approx):")
        st.markdown("- 800×600 px image → capacity ≈ 800*600*3/8 = 180000 bytes (≈ 176 KB)")
        st.markdown("- Jika pesan terenkripsi melebihi kapasitas, embedding akan gagal.")
        st.markdown("Praktik terbaik: gunakan gambar beresolusi tinggi atau kurangi ukuran pesan. Hindari menyimpan stego sebagai JPG karena kompresi lossy merusak LSB.")

# ---------------------------
# Mode: Tentang
# ---------------------------
else:
    st.markdown('<div class="header"><div class="app-title">ℹ️ Tentang StegoVault</div></div>', unsafe_allow_html=True)
    st.markdown("""
**StegoVault** — aplikasi demonstrasi steganografi berbasis LSB yang dipadukan kriptografi AES.

**Fitur utama**
- Enkripsi pesan teks dengan AES (password-based).
- Menyisipkan ciphertext ke LSB piksel RGB.
- Ekstraksi + dekripsi kembali ke plaintext.
- Dashboard: capacity info, sample generator, download stego PNG.

**Catatan penting**
- JPEG bersifat *lossy* — jangan menyimpan stego image sebagai JPG jika ingin menjaga data tersembunyi. Aplikasi ini menghasilkan PNG hasil embedding agar informasi tetap aman.
- Metode LSB sederhana dan rentan terhadap analisis steganalitik; untuk kebutuhan keamanan tingkat tinggi, pelajari teknik stego berbasis DCT atau algoritma robust lainnya.
- Password harus dijaga; jika hilang, data tidak dapat dikembalikan.
    """)
    st.markdown("**Lisensi & penggunaan:** untuk tujuan pembelajaran dan penelitian. Jangan gunakan untuk aktivitas ilegal.")
