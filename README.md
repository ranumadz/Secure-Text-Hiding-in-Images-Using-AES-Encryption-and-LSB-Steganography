# 🔐 Secure Text Hiding in Images Using AES Encryption and LSB Steganography

This project demonstrates a **hybrid approach to information security** by combining **AES cryptography** with **LSB (Least Significant Bit) steganography**.  

Messages are first **encrypted with AES**, then **hidden inside image pixels** using LSB, ensuring both:
- **Confidentiality** → content is encrypted and unreadable without the password.  
- **Stealth** → ciphertext is invisibly embedded into the image.  

The app is built with **Streamlit**, providing an interactive dashboard for easy testing and demonstration.  

---

## 🚀 Features
- **Encrypt & Embed**: Hide secret messages inside an image using AES-128 + LSB.  
- **Extract & Decrypt**: Retrieve and decrypt messages with the correct password.  
- **Dashboard**:  
  - Capacity analysis (how many bytes fit into an image).  
  - Sample image generator for quick tests.  
  - Technical information (AES mode, key derivation, storage format).  
- **Safe Output**: Converts all outputs to PNG (lossless), preventing JPEG compression from destroying hidden bits.  

---

## 🖼️ Demo (Streamlit App)
Run locally:  
```bash
streamlit run app.py
