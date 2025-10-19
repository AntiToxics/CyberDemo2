"""
Author: Gilad Elran
Program name: Enryption3.py
Description:
    This program can encrypt or decrypt text messages based on a given table.
    - If run with the argument "encrypt", it asks the user for a message,
      encrypts it, and saves it to msg_encrypted.txt.
    - If run with the argument "decrypt", it reads the file and decrypts the message.
    - If there is an invalid argument the program will not decrypt nor encrypt.
    The program assumes all characters appear in the table.

Date: 2025-10-09
"""

import sys
import logging

# --- CONSTANTS ---
ENCRYPTED_FILE = "msg_encrypted.txt"
LOG_FILE = "encryption.log"

# --- LOGGING CONFIGURATION ---
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filemode="a"
)


# --- FUNCTIONS ---
def encrypt_message(message, enc_table):
    """
    Encrypts a message using the given table.
    Each character is replaced by its code, separated by commas.
    Allows empty messages.
    message: str , enc_table: dictionary
    returns encrypted_text -> (str)
    """
    if message == "":
        logging.info("Empty message provided for encryption.")
        return ""
    try:
        encrypted_list = [str(enc_table[ch]) for ch in message]
        encrypted_text = ",".join(encrypted_list)
        logging.info(f"Message encrypted successfully: {encrypted_text}")
        return encrypted_text
    except KeyError as e:
        logging.error(f"Encryption failed: Character '{e.args[0]}' not in table.")
        return None


def decrypt_message(encrypted_text, dec_table):
    """
    Decrypts an encrypted string back to text.
    Each number represents a character from the table.
    encrypted_text: str , dec_table: dictionary
    returns decrypted_text -> (str)
    """
    if encrypted_text == "":
        logging.info("Empty encrypted text provided for decryption.")
        return ""

    try:
        numbers = [int(x) for x in encrypted_text.split(",")]
    except ValueError:
        logging.error("Corrupted encrypted file (non-numeric data found).")
        return None

    reverse_table = {v: k for k, v in dec_table.items()}
    try:
        decrypted_chars = [reverse_table[num] for num in numbers]
        decrypted_text = "".join(decrypted_chars)
        logging.info("Message decrypted successfully.")
        return decrypted_text
    except KeyError as e:
        logging.error(f"Decryption failed: Unknown number '{e.args[0]}'.")
        return None


def load_table():
    """
    Returns a sample encryption table.
    """
    return {
        "A": 56, "B": 57, "C": 58, "D": 59, "E": 40, "F": 41, "G": 42, "H": 43, "I": 44,
        "J": 45, "K": 46, "L": 47, "M": 48, "N": 49, "O": 60, "P": 61, "Q": 62,
        "R": 63, "S": 64, "T": 65, "U": 66, "V": 67, "W": 68, "X": 69, "Y": 10,
        "Z": 11, "a": 12, "b": 13, "c": 14, "d": 15, "e": 16, "f": 17, "g": 18,
        "h": 19, "i": 30, "j": 31, "k": 32, "l": 33, "m": 34, "n": 35, "o": 36,
        "p": 37, "q": 38, "r": 39, "s": 90, "t": 91, "u": 92, "v": 93, "w": 94,
        "x": 95, "y": 96, "z": 97, " ": 98, ",": 99, ".": 100, "’": 101, "!": 102,
        "-": 103
    }


def main():
    """
    Main function to handle encrypt/decrypt modes.
    Reads argv to determine which operation to perform.
    """
    if len(sys.argv) < 2:
        print("Usage: python Encryption.py [encrypt/decrypt]")
        logging.error("No mode provided in command line arguments.")
        return

    mode = sys.argv[1].lower()
    table = load_table()

    if mode == "encrypt":
        message = input("Enter message to encrypt: ")
        encrypted = encrypt_message(message, table)
        if encrypted is None:
            logging.error("Encryption returned None — failed.")
            print("Error: Encryption failed.")
            return
        try:
            with open(ENCRYPTED_FILE, "w") as f:
                f.write(encrypted)
            logging.info(f"Encrypted message saved to {ENCRYPTED_FILE}.")
            print(f"Message encrypted and saved to {ENCRYPTED_FILE}")
        except Exception as e:
            logging.error(f"Error writing to file: {e}")
            print(f"Error writing to file: {e}")

    elif mode == "decrypt":
        try:
            with open(ENCRYPTED_FILE, "r") as f:
                encrypted_text = f.read().strip()
        except FileNotFoundError:
            logging.error(f"File not found: {ENCRYPTED_FILE}")
            print(f"Error: {ENCRYPTED_FILE} not found,need to encrypt before decrypting.")
            return
        except Exception as e:
            logging.error(f"Error reading file: {e}")
            print(f"Error reading file: {e}")
            return

        decrypted = decrypt_message(encrypted_text, table)
        if decrypted is not None:
            print("Decrypted message:")
            print(decrypted)
        else:
            logging.error("Decryption returned None — failed.")
            print("Error: Failed to decrypt message.")
    else:
        print("Error: Invalid mode. Use 'encrypt' or 'decrypt'.")
        logging.error(f"Invalid mode entered: {mode}")


# --- ASSERT TESTS (placed before main run) ---
if __name__ == "__main__":
    assertaion_table = load_table()

    # Disable logging during tests
    logging.disable(logging.CRITICAL)

    try:
        # --- Basic Tests ---
        assert encrypt_message("HI", assertaion_table) == "43,44", "Encrypt test failed"
        assert decrypt_message("43,44", assertaion_table) == "HI", "Decrypt test failed"
        assert encrypt_message("", assertaion_table) == "", "Empty encrypt failed"
        assert decrypt_message("", assertaion_table) == "", "Empty decrypt failed"

        # Re-enable logging
        logging.disable(logging.NOTSET)
        logging.info("All assert tests passed successfully.")

    except AssertionError as error:
        # Re-enable logging to record the failure
        logging.disable(logging.NOTSET)
        logging.error(f"Assertion test failed: {error}")
        sys.exit(1)

    main()

