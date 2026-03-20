import serial
import time
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes, serialization
from compress import lzss_compress
from encrypt import aes_gcm_encrypt
# ================= CONFIG =================
PORT          = "COM4"
BAUD          = 115200
CHUNK_SIZE    = 128
APP_BIN       = r"C:\Users\HP\Documents\work_space\Embedded_Secure_Encryp_Comp\Application\Debug\Application.bin"
SIGNED_BIN = os.path.join( r"C:\Users\HP\Documents\work_space\Embedded_Secure_Encryp_Comp\Out", "Application_compressed_encrypt.bin")
ACK           = b'\x79'
ERR           = b'\x1F'
END           = 0xFFFF

#hado dyal ECDSA
PRIV_KEY_FILE = "private_key.pem"
PUB_KEY_FILE  = "public_key.pem"
SIG_SIZE = 64

# Hadi Qbal mandir Encrypt:
# [ compressed .bin ] + [ original_size 4B ] + [ ECDSA sig 64B ]
# What travels over UART:
# [ original_size 4B ] → [ compressed chunks ] → END → [ SIG 64B ]

# Hadi faxh tzadt Encrypt:
# UART: [ IV 12B ] → [ original_size 4B ] → [ encrypted chunks ] → END → [ Tag 16B ] → [ SIG 64B ]


ser = serial.Serial(PORT, BAUD, timeout=5)

# ================= dispaly Key =================
def print_public_key_c_array():
    with open(PUB_KEY_FILE, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    pub_numbers = public_key.public_numbers()
    raw_pub     = pub_numbers.x.to_bytes(32, 'big') + pub_numbers.y.to_bytes(32, 'big')
    print("\n[KEYGEN] Current public key C array for flash_if.h:")
    print("static const uint8_t PUBLIC_KEY[64] = {")
    hex_vals = [f"0x{b:02X}" for b in raw_pub]
    for i in range(0, 64, 8):
        print("    " + ", ".join(hex_vals[i:i+8]) + ",")
    print("};\n")
# ================= KEY MANAGEMENT =================
def generate_keys():
    print("[KEYGEN] Generating new ECDSA P-256 keypair...")
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key  = private_key.public_key()

    with open(PRIV_KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(PUB_KEY_FILE, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    pub_numbers = public_key.public_numbers()
    raw_pub     = pub_numbers.x.to_bytes(32, 'big') + pub_numbers.y.to_bytes(32, 'big')

    print("[KEYGEN] Keys saved: private_key.pem, public_key.pem")
    print("[KEYGEN] Copy this C array into your bootloader (flash_if.h):\n")
    print("static const uint8_t PUBLIC_KEY[64] = {")
    hex_vals = [f"0x{b:02X}" for b in raw_pub]
    for i in range(0, 64, 8):
        print("    " + ", ".join(hex_vals[i:i+8]) + ",")
    print("};\n")
    print("[KEYGEN] !! REFLASH BOOTLOADER WITH NEW PUBLIC KEY BEFORE FLASHING APP !!\n")
    return private_key

def load_or_generate_keys():
    if not os.path.exists(PRIV_KEY_FILE) or not os.path.exists(PUB_KEY_FILE):
        print("[KEYGEN] No keys found — generating new keypair...")
        return generate_keys()
    with open(PRIV_KEY_FILE, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    print("[KEYGEN] Loaded existing private key.")
    return private_key

# ================= BUILD SIGNED BUNDLE =================
def build_signed_bundle(private_key):
    """
    SIGNED_BIN layout: [ IV 12B ] + [ encrypted ] + [ Tag 16B ] + [ original_size 4B ] + [ SIG 64B ]
    UART layout: [ IV 12B ] → [ original_size 4B ] → [ encrypted chunks ] → END → [ Tag 16B ] → [ SIG 64B ]
    Returns: (iv, encrypted, tag, original_size, raw_sig)
    """
    os.makedirs(r"C:\Users\HP\Documents\work_space\Embedded_Secure_Encryp_Comp\Out", exist_ok=True)
    # Step 1: Read raw firmware 
    with open(APP_BIN, "rb") as f:
        firmware = f.read()
    # Step 2 : compress firmware
    compressed     = lzss_compress(firmware)
    original_size  = len(firmware)
    comp_ratio     = len(compressed) / original_size * 100
    print(f"[LZSS] Original : {original_size} bytes")
    print(f"[LZSS] Compressed: {len(compressed)} bytes  ({comp_ratio:.1f}%)")
    #END compress
    # Step 2 : encrypt firmware
    iv, encrypted, tag = aes_gcm_encrypt(compressed)    
    #END Enrypt
    # Step 4 : Sign the RAW firmware (STM32 verifies after decompress)
    # ===== TEST 2: corrupt AFTER signing =====
    #firmware = bytearray(firmware)
    #firmware[100] ^= 0xFF
    #firmware = bytes(firmware)
    # =========================================
    # Sign fresh — ECDSA P-256 over full firmware
    der_sig = private_key.sign(firmware, ec.ECDSA(hashes.SHA256()))
    r, s    = decode_dss_signature(der_sig)
    raw_sig = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    print(f"[SIGN] R: {r:064X}")
    print(f"[SIGN] S: {s:064X}")
    # Step 4: Save bundle to disk
    orig_size_bytes = original_size.to_bytes(4, 'little')
    with open(SIGNED_BIN, "wb") as f:
        f.write(iv)           # 12 bytes
        f.write(encrypted)    # compressed size
        f.write(tag)          # 16 bytes
        f.write(orig_size_bytes)  # 4 bytes
        f.write(raw_sig)      # 64 bytes
    print(f"[BUILD] Saved : {SIGNED_BIN}")

    return iv, encrypted, tag, original_size, raw_sig

# ================= UTILS =================
def wait_byte(expected, timeout=5):
    start = time.time()
    while True:
        if ser.in_waiting:
            b = ser.read(1)
            print(f"[RX RAW]: {b}")
            if b == expected:
                return True
            if b == ERR:
                print("[ERR] STM32 returned ERROR")
                return False
        if time.time() - start > timeout:
            print("[ERR] TIMEOUT")
            return False

def send_command(cmd):
    ser.write(cmd)
    ser.flush()
    print(f"[TX]: {cmd}")

def listen_for_app(timeout=5):
    print("[INFO] Listening for APP message...")
    time.sleep(0.2)
    start  = time.time()
    buffer = b""
    while time.time() - start < timeout:
        if ser.in_waiting:
            data    = ser.read(ser.in_waiting)
            buffer += data
            print(f"[APP MSG]: {data.decode('utf-8', errors='ignore')}")
        time.sleep(0.05)
    if not buffer:
        print("[INFO] No message from APP")

# ================= FLASH =================
def flash_firmware(iv,encrypted, tag,original_size, raw_sig):
    """
UART layout: [ IV 12B ] → [ Tag 16B ] → [ original_size 4B ] → [ encrypted chunks ] → END → [ SIG 64B ]
STM32 flow:
  receive IV + Tag + original_size
  → decrypt + decompress chunks → flash
  → ECDSA verify → ACK + jump
"""
    # Step 1: Wait erase ACK
    print("[FLASH] Waiting erase ACK...")
    if not wait_byte(ACK, timeout=10):
        print("[FLASH] Erase failed")
        return False
    print("[FLASH] Erase OK")
    #step 2 : send IV initialized vector 
    send_command(iv)
    if not wait_byte(ACK): 
        return False
    # Step 6: Send tag
    send_command(tag)
    if not wait_byte(ACK): 
        return False
    # Step 3: Send size origin of compress data
    send_command(original_size.to_bytes(4, 'little'))
    if not wait_byte(ACK): 
        return False
    # Step 4: Send .bin decrepted data as chunks
    chunk_id = 0
    offset   = 0
    total    = len(encrypted)

    while offset < total:
        chunk      = encrypted[offset: offset + CHUNK_SIZE]
        chunk_size = len(chunk)
        send_command(chunk_size.to_bytes(2, 'little'))
        if not wait_byte(ACK):
            return False
        send_command(chunk)
        if not wait_byte(ACK):
            return False
        print(f"[FLASH] Chunk {chunk_id:03d} OK  ({offset + chunk_size}/{total} bytes)")
        chunk_id += 1
        offset   += chunk_size
    # Step 5: Send END marker
    print("[FLASH] Sending END marker...")
    send_command(END.to_bytes(2, 'little'))
    if not wait_byte(ACK):
        return False
    # Step 7: Send 64-byte ECDSA signature (R || S, big-endian)
    print(f"[FLASH] Sending signature (64 bytes)...")
    # ===== TEST 3: corrupt signature =====
    #raw_sig = bytearray(raw_sig)
    #raw_sig[0] ^= 0xFF
    #raw_sig = bytes(raw_sig)
    send_command(raw_sig)
    # Step 8: Wait STM32 verify result
    print("[FLASH] Waiting signature verification result...")
    if not wait_byte(ACK, timeout=10):
        print("[FLASH] Signature INVALID — STM32 erased app flash!")
        return False
    print("[FLASH] Signature VALID — STM32 jumping to app!")
    return True

# ================= BOOTLOADER MODE =================
def bootloader_mode():
    print("\n--- BOOTLOADER MODE ---")
    print("Commands: F = flash, J = jump to app\n")

    while True:
        cmd = input(">> ").lower()

        if cmd == 'f':
            private_key                    = load_or_generate_keys()
            iv, encrypted, tag, original_size, raw_sig = build_signed_bundle(private_key)
            send_command(b'F')
            if wait_byte(ACK, timeout=3):
                if flash_firmware(iv, encrypted, tag, original_size, raw_sig) :
                    print("[DONE] Flash complete!")
                    listen_for_app(timeout=8)
                    application_mode()
                    return
            else:
                print("[ERR] No response from bootloader!")

        elif cmd == 'j':
            send_command(b'J')
            if wait_byte(ACK, timeout=3):
                print("[INFO] Jumping to APP...")
                listen_for_app(timeout=3)
                application_mode()
                return
            else:
                print("[ERR] No response!")

        else:
            print("[INFO] Unknown command. Use F or J.")

# ================= APPLICATION MODE =================
def application_mode():
    print("\n--- APPLICATION MODE ---")
    print("Commands: T = toggle LED, R = reset to bootloader\n")

    try:
        while True:
            try:
                if ser.in_waiting:
                    data = ser.read(ser.in_waiting)
                    print(f"[APP RX]: {data.decode('utf-8', errors='ignore')}")
            except Exception:
                pass

            user = input("> ").strip().upper()
            if user == 'T':
                send_command(b'T')
            elif user == 'R':
                send_command(b'R')
                print("[INFO] Resetting to bootloader...")
                ser.reset_input_buffer()
                print("[INFO] Bootloader ready!")
                bootloader_mode()
    except KeyboardInterrupt:
        print("\n[EXIT]")
        ser.close()
# ================= MAIN =================
def main():
    print(f"[INFO] Connected to {PORT} @ {BAUD}")
    print("[INFO] Press RESET on board, then choose command")
    print("Commands: F = flash, J = jump\n")

    load_or_generate_keys()
    #print_public_key_c_array()
    time.sleep(0.5)

    while True:
        cmd = input(">> ").lower()

        if cmd == 'f':
            print("[INFO] Syncing with bootloader...")
            start  = time.time()
            synced = False
            while time.time() - start < 10:
                ser.reset_input_buffer()
                ser.write(b'F')
                ser.flush()
                time.sleep(0.2)
                if ser.in_waiting:
                    b = ser.read(1)
                    if b == ACK:
                        print("[INFO] Bootloader ready!")
                        synced = True
                        break
            if synced:
                private_key                   = load_or_generate_keys()
                iv, encrypted, tag , original_size, raw_sig = build_signed_bundle(private_key)
                if flash_firmware(iv, encrypted, tag, original_size, raw_sig) :
                    print("[DONE] Flash complete!")
                    listen_for_app(timeout=8)
                    application_mode()
                    return
            else:
                print("[ERR] No response — press RESET and try again")

        elif cmd == 'j':
            print("[INFO] Syncing with bootloader...")
            start  = time.time()
            synced = False
            while time.time() - start < 10:
                ser.reset_input_buffer()
                ser.write(b'J')
                ser.flush()
                time.sleep(0.2)
                if ser.in_waiting:
                    b = ser.read(1)
                    if b == ACK:
                        print("[INFO] Bootloader ready!")
                        synced = True
                        break
            if synced:
                print("[INFO] Jumping to APP...")
                listen_for_app(timeout=3)
                application_mode()
                return
            else:
                print("[ERR] No response — press RESET and try again")

        else:
            print("[INFO] Unknown command. Use F or J.")

if __name__ == "__main__":
    try:
        main()
    finally:
        ser.close()
