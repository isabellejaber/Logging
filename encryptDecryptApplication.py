from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import argparse
import logging

# While only info and error messages were used for this application, these are the logging message types and their uses
# DEBUG: Detailed information, typically of interest only when diagnosing problems.
# INFO: Confirmation that things are working as expected.
# WARNING: An indication that something unexpected happened, or indicative of some problem in the near future
#   (e.g. ‘disk space low’). The software is still working as expected.
# ERROR: Due to a more serious problem, the software has not been able to perform some function.
# CRITICAL: A serious error, indicating that the program itself may be unable to continue running.

logger = logging.getLogger(__name__)
logging.basicConfig(filename='logs.log', encoding='utf-8', level=logging.DEBUG)

def derive_key(key):
    # Derive a 32-byte (256-bit) key using PBKDF2
    salt = b'salt1234'  # You should use a unique salt for each application
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,  # Adjust the number of iterations as needed for your security requirements
        backend=default_backend()
    )
    logger.info("Salted key hashed using SHA256 algorithm")
    return kdf.derive(key)

def encrypt(plaintext, key):
    key = derive_key(key.encode('utf-8'))
    cipher = Cipher(algorithms.AES(key), modes.CFB8(key[:16]), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt(ciphertext, key):
    key = derive_key(key.encode('utf-8'))
    cipher = Cipher(algorithms.AES(key), modes.CFB8(key[:16]), backend=default_backend())
    decryptor = cipher.decryptor()
    ciphertext_bytes = base64.b64decode(ciphertext)
    plaintext = decryptor.update(ciphertext_bytes) + decryptor.finalize()
    return plaintext.decode('utf-8')

def main():
    parser = argparse.ArgumentParser(description="Simple AES Encryption and Decryption")
    parser.add_argument('mode', choices=['encrypt', 'decrypt'], help='Select "encrypt" or "decrypt" mode')
    parser.add_argument('-p', '--plaintext', help='Text to be encrypted or decrypted')
    parser.add_argument('-k', '--key', help='Encryption/Decryption key')

    args = parser.parse_args()

    if args.mode == 'encrypt':
        if not args.plaintext or not args.key:
            logger.error("Both plaintext and key are required for encryption.")
            logger.info("PLEASE TRY AGAIN\n")
            return

        encrypted_text = encrypt(args.plaintext.encode('utf-8'), args.key)
        logger.info("AES encryption applied to " + args.plaintext + " using the salted key")
        print(f"Encrypted Text: {encrypted_text}")
        logger.info(f"Encrypted text is: {encrypted_text}")
        logger.info("ENCRYPTION COMPLETE\n")

    elif args.mode == 'decrypt':
        if not args.plaintext or not args.key:
            logger.error("Both ciphertext and key are required for decryption.")
            logger.info("PLEASE TRY AGAIN\n")
            return
        decrypted_text = decrypt(args.plaintext, args.key)
        logger.info("AES decryption applied to " + args.plaintext + " using the salted key")
        print(f"Decrypted Text: {decrypted_text}")
        logger.info(f"Decrypted text is: {decrypted_text}")
        logger.info("DECRYPTION COMPLETE\n")



if __name__ == "__main__":
    main()
