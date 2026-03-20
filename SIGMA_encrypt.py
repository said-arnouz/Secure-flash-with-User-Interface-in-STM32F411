from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# ================= AES KEY =================
# 32 bytes = AES-256
AES_KEY = bytes([
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
])
# ================= ENCRYPT =================
def aes_gcm_encrypt(data: bytes):
    """
    Input  : compressed firmware bytes
    Output : (iv, encrypted, tag)
      iv        = 12 bytes random
      encrypted = same size as input
      tag       = 16 bytes
    """
    # random IV (12 bytes) baxh tqad Counter block (4 bytes)w tkon f total = 16 bytes block AES
    iv       = os.urandom(12)       
    aesgcm   = AESGCM(AES_KEY)       # Algo GCM
    enc_tag  = aesgcm.encrypt(iv, data, None)
    encrypted = enc_tag[:-16]        #
    tag       = enc_tag[-16:]        # 16 bytes = tag
    return iv, encrypted, tag

if __name__ == "__main__":
    from compress import lzss_compress, lzss_decompress
    
    APP_BIN = r"C:\Users\HP\Documents\work_space\Embedded_Secure_Encryp_Comp\Application\Debug\Application.bin"  # ← زيد هاد السطر
    
    with open(APP_BIN, "rb") as f:
        firmware = f.read()
    
    # compress
    compressed = lzss_compress(firmware)
    
    # encrypt
    iv, encrypted, tag = aes_gcm_encrypt(compressed)
    
    # decrypt
    aesgcm    = AESGCM(AES_KEY)
    decrypted = aesgcm.decrypt(iv, encrypted + tag, None)
    
    # decompress
    recovered = lzss_decompress(decrypted, len(firmware))
    
    # verify
    if recovered == firmware:
        print("PASS — pipeline correct!")
    else:
        print("FAIL — data corrupted!")
        for i in range(min(len(firmware), len(recovered))):
            if firmware[i] != recovered[i]:
                print(f"First diff at byte {i}: original=0x{firmware[i]:02X} recovered=0x{recovered[i]:02X}")
                break