"""
    This is the encryption module which contains the StreamEncryption and BlockEncryption classes.
"""

from os import urandom, system
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
from secrets import token_bytes
    
class BlockEncryption:
    """
        The Block Encryption class has methods for performing encryption using
        128-bit AES block encryption in Cipher Block Chaining (CBC) mode. It also
        uses a Hash-Based Message Authentication Code (HMAC), generated using the SHA-256
        cryptographic hash function, to perform authentication and data integrity verification.
    """

    def __init__(self):
        """
            The constructor method for the BlockEncryption class. 

            Parameters
            ----------
            None

            Returns
            -------
            An instance of the BlockEncryption class.
        """
        self.__secret = None
        self.__fernet = None


    def read_key(self, path: str) -> bool:
        """
            Reads a secret key.

            Reads a 128-bit secret key from the file located at the given path.
            It also sets the internal secret key value to the value read from 
            the file.

            Parameters
            ----------
            path: str - The path to the secret key file.

            Returns
            -------
            bool - True on success, or False on failure.
        """
        try:
            with open(path, "rb") as f:
                self.__secret = f.read()
            self.__fernet = Fernet(self.__secret)
            return True
        except FileNotFoundError:
            return False


    def encrypt(self, cleartext: bytes) -> bytes:
        """
            Decrypts the given bytes.

            Takes the given cleartext bytes and encrypts them using
            128-bit AES block cipher and the shared secret key.

            Parameters
            ----------
            cleartext: bytes - The bytes to encrypt.

            Returns
            -------
            bytes - The encrypted bytes.
        """
        return self.__fernet.encrypt(cleartext)


    def decrypt(self, ciphertext: bytes) -> bytes:
        """
            Decrypts the given bytes.

            Takes the given ciphertext bytes and decrypts them using
            128-bit AES block cipher and the shared secret key.

            Parameters
            ----------
            ciphertext: bytes - The bytes to decrypt.

            Returns
            -------
            bytes - The decrypted bytes.
        """
        return self.__fernet.decrypt(ciphertext)


class StreamEncryption:
    """
        The Stream Encryption class enables simple stream encryption utilties.
        It uses the ChaCha20 stream cipher and provides functions to 
        perform encryption and decryption.
    """


    def __init__(self):
        """
            StreamEncryption constructor method.

            The constructor method returns an instance of the StreamEncryption class.

            Parameters
            ----------
            None

            Returns
            -------
            An instance of the StreamEncryption class.
        """
        self.__secret = None
        self.__nonce = None
        self.__cipher = None
        self.__algorithm = None
        self.__encryptor = None
        self.__decryptor = None


    def generate_nonce(self):
        """
            Generates a random 16 byte nonce and saves it as a file named 'nonce.bin'.

            Parameters
            ----------
            None

            Returns
            -------
            None
        """
        with open("nonce.bin", "wb") as f:
            f.write(urandom(16))


    def read_nonce(self, file_path) -> bool:
        """
            Read a 16 byte nonce from a file.

            Reads the 16 byte nonce from the given file specified by file_path and 
            sets the internal nonce variable to what was read from the file.

            Parameters
            ----------
            file_path: str - The path to the nonce file.

            Returns
            -------
            bool - True on success, False on failure.
        """
        try:
            with open(file_path, "rb") as f:
                self.__nonce = f.read()
            return True
        except FileNotFoundError:
            return False


    def generate_secret(self):
        """
            Generates a secret key.

            Generates a cryptographically secure secret key that is
            32 bytes long. Saves it to a file named 'secret.key'.

            Parameters
            ----------
            None

            Returns
            -------
            None
        """
        with open("secret.key", "wb") as f:
            f.write(token_bytes(32))


    def read_secret(self, file_path: str) -> bool:
        """
            Reads a secret key.

            Reads a 32-byte secret key from the given file_path and
            sets the internal secret key value.

            Parameters
            ----------
            file_path: str - The path to the secret key file.

            Returns
            -------
            bool - True on success, False on failure.
        """
        try:
            with open(file_path, "rb") as f:
                self.__secret = f.read()
            return True
        except FileNotFoundError:
            return False


    def initialize_encryption_context(self) -> bool:
        """
            Initializes the encryption context.

            Initializes instance variables that are necessary to perform
            encrypt and decrypt functions. A nonce and secret key must have
            been read, using read_nonce() and read_secret() respectively, before 
            this function is called. If read_nonce() and read_secret() have not
            been called before this function, then this function will do nothing.
            If the read_nonce() and read_secret() functions were called prior to this
            function, then it will initalize the encryption context.
            
            Parameters
            ----------
            None

            Returns
            -------
            bool - True on success, False on failure.
        """
        if self.__nonce != None and self.__secret != None:
            self.__algorithm = ChaCha20(self.__secret, self.__nonce)
            self.__cipher = Cipher(self.__algorithm, mode=None)
            self.__encryptor = self.__cipher.encryptor()
            self.__decryptor = self.__cipher.decryptor()
            return True
        return False


    def encrypt(self, cleartext: bytes) -> bytes:
        """
            Encrypts the given cleartext.

            Encrypts the given cleartext using the ChaCha20 stream cipher and
            shared secret key.

            Parameters
            ----------
            cleartext: bytes - The bytes to encrypt with the ChaCha20 stream cipher.

            Returns
            -------
            bytes - The encrypted bytes.
        """
        return self.__encryptor.update(cleartext)


    def decrypt(self, ciphertext: bytes):
        """
            Decrypts the given ciphertext.

            Decrypts the given ciphertext using the ChaCha20 stream cipher and
            established secret key.

            Parameters
            ----------
            ciphertext: bytes - The bytes to decrypt with the ChaCha20 stream cipher.

            Returns
            -------
            bytes - The decrypted bytes.
        """
        return self.__decryptor.update(ciphertext)

