import secrets
import typing

from cryptography.hazmat.primitives import constant_time, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.kbkdf import KBKDFHMAC, CounterLocation, Mode

if typing.TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey


class SessionKeyNotEstablishedError(Exception):
    pass


class CryptProtocol:
    # Warning! 
    # It should be noted the current implemntation does nothing to prevent:
    # - Using the same IV/nounce across multiple messages in the same session
    # - Replay attacks by sending the same message over and over again in the same session
    
    AES_KEY_SIZE: int = 32
    AES_NONCE_SIZE: int = 12
    SIGNATURE_SIZE: int = 64
    REAL_INITIAL_MESSAGE_SIZE: int = 604
    MAX_INITIAL_MESSAGE_SIZE: int = 1024

    def __init__(self, pre_shared_key: bytes) -> None:
        self.pre_shared_key: bytes = pre_shared_key
        self.asymmetric_key: RSAPrivateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )
        self.key_exchange_key: X25519PrivateKey | None = None
        self.signing_key: Ed25519PrivateKey = Ed25519PrivateKey.generate()
        self.session_crypt: AESGCM | None = None
        self.session_key: bytes | None = None
        self.pre_shared_key_rotated: bool = False

    @staticmethod
    def generate_random_psk() -> bytes:
        return secrets.token_bytes(CryptProtocol.AES_KEY_SIZE)

    @staticmethod
    def generate_kdf() -> KBKDFHMAC:
        return KBKDFHMAC(
            algorithm=hashes.SHA256(),
            mode=Mode.CounterMode,
            length=32,
            rlen=4,
            llen=4,
            location=CounterLocation.BeforeFixed,
            label=None,
            context=None,
            fixed=None,
        )

    def session_state_check(self) -> None:
        if self.session_crypt is None or self.session_key is None:
            raise SessionKeyNotEstablishedError

        # If there is a KEX key, destroy it
        if self.session_crypt and self.key_exchange_key:
            self.key_exchange_key = None

        if not self.pre_shared_key_rotated:
            # Rotate the PSK
            # Get the KDF
            kdf: KBKDFHMAC = self.generate_kdf()
            self.pre_shared_key = kdf.derive(self.session_key + self.pre_shared_key)

            # Set state
            self.pre_shared_key_rotated = True

    def kex_state_check(self) -> None:
        # Reset state to false
        if self.pre_shared_key_rotated:
            self.pre_shared_key_rotated = False

        # Generate the ephemeral DH key if we don't have one
        if self.key_exchange_key is None:
            self.key_exchange_key: X25519PrivateKey = X25519PrivateKey.generate()

    def generate_initial_message(self, peer: "CryptProtocol") -> bytes:
        self.kex_state_check()

        # Get the public key to send as bytes
        public_key_to_transmit: bytes = self.key_exchange_key.public_key().public_bytes_raw()

        # Encrypt it using peers public key
        encrypted_public_kex_key: bytes = peer.asymmetric_key.public_key().encrypt(
            public_key_to_transmit,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )

        # Get the signature for the public key
        public_kex_key_signature: bytes = self.signing_key.sign(public_key_to_transmit)

        # Pack the message
        msg: bytes = encrypted_public_kex_key + public_kex_key_signature

        # Encrypt the message
        encrypter: AESGCM = AESGCM(self.pre_shared_key)
        msg_nonce: bytes = secrets.token_bytes(self.AES_NONCE_SIZE)
        encrypted_msg: bytes = encrypter.encrypt(msg_nonce, msg, None)

        # Generate some random junk data padding to fill upto 1KB of data
        junk_padding_size: int = secrets.choice(
            range(self.REAL_INITIAL_MESSAGE_SIZE, self.MAX_INITIAL_MESSAGE_SIZE + 1)
        )
        junk_data: bytes = secrets.token_bytes(junk_padding_size)

        return msg_nonce + encrypted_msg + junk_data

    def parse_initial_message(self, initial_msg: bytes, peer: "CryptProtocol") -> None:
        # Split the message into parts
        nonce: bytes = initial_msg[: self.AES_NONCE_SIZE]
        encrypted_msg: bytes = initial_msg[self.AES_NONCE_SIZE : self.REAL_INITIAL_MESSAGE_SIZE]

        # Decrypt the message
        decrypter: AESGCM = AESGCM(self.pre_shared_key)
        decrypted_msg: bytes = decrypter.decrypt(nonce, encrypted_msg, None)

        # Split the message into it's appropriate parts
        encrypted_public_key: bytes = decrypted_msg[: -self.SIGNATURE_SIZE]
        public_key_signature: bytes = decrypted_msg[-self.SIGNATURE_SIZE :]

        # Decrypt the KEX key
        decrypted_public_key: bytes = self.asymmetric_key.decrypt(
            encrypted_public_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )

        # Check the signature matches
        peer.signing_key.public_key().verify(public_key_signature, decrypted_public_key)

        # Convert to an actual key
        peer_public_key: X25519PublicKey = X25519PublicKey.from_public_bytes(decrypted_public_key)

        # Generate a key_exchange_key if we don't have one yet
        if self.key_exchange_key is None:
            self.key_exchange_key = X25519PrivateKey.generate()

        # Derive the shared DH key
        shared_key: bytes = self.key_exchange_key.exchange(peer_public_key)

        # Make a KBKDF to derive the session key from
        kdf: KBKDFHMAC = self.generate_kdf()

        # Derive the session key
        self.session_key: bytes = kdf.derive(shared_key)
        self.session_crypt = AESGCM(self.session_key)

    def encrypt(self, msg: bytes) -> bytes:
        # Check object state
        self.session_state_check()

        # Generate the nonce
        nonce: bytes = secrets.token_bytes(self.AES_NONCE_SIZE)

        # Encrypt using the session key
        return nonce + self.session_crypt.encrypt(nonce, msg, None)

    def decrypt(self, msg: bytes) -> bytes:
        # Check object state
        self.session_state_check()

        # Split the message into its appropriate parts
        nonce: bytes = msg[: self.AES_NONCE_SIZE]
        encrypted_msg: bytes = msg[self.AES_NONCE_SIZE :]

        # Decrypt the message
        return self.session_crypt.decrypt(nonce, encrypted_msg, None)

    def finalize(self) -> None:
        # Reset the key exchange key if it's still there
        self.key_exchange_key = None

        # If we have a session key, ratchet the PSK and reset the session key
        if self.session_crypt:
            # Reset session key state
            self.session_crypt = None

        if self.session_key:
            self.session_key = None

        # Reset PSK rot state
        self.pre_shared_key_rotated = False


def main() -> None:
    initial_key: bytes = CryptProtocol.generate_random_psk()

    alice: CryptProtocol = CryptProtocol(initial_key)
    bob: CryptProtocol = CryptProtocol(initial_key)

    alice_initial_message: bytes = alice.generate_initial_message(bob)
    bob.parse_initial_message(alice_initial_message, alice)

    bob_initial_message: bytes = bob.generate_initial_message(alice)
    alice.parse_initial_message(bob_initial_message, bob)

    initial_msg: bytes = b"Hello there!"
    encrypted_msg: bytes = alice.encrypt(initial_msg)
    decrypted_msg: bytes = bob.decrypt(encrypted_msg)

    # Finalize the objects
    alice.finalize()
    bob.finalize()

    # Check everything matches
    result: bool = constant_time.bytes_eq(initial_msg, decrypted_msg)
    print("Messages match? ", result)

    # Check roll over for next session
    alice_initial_message_2 = alice.generate_initial_message(bob)
    bob.parse_initial_message(alice_initial_message_2, alice)

    bob_initial_message_2: bytes = bob.generate_initial_message(alice)
    alice.parse_initial_message(bob_initial_message_2, bob)

    second_msg: bytes = b"Oh hello again!"
    encrypted_msg = alice.encrypt(second_msg)
    decrypted_msg = bob.decrypt(encrypted_msg)

    # Finalize the objects again
    alice.finalize()
    bob.finalize()

    result = constant_time.bytes_eq(second_msg, decrypted_msg)
    print("Messages match? ", result)

    # Replay attack - This will get the objects into a weird state, i know
    # This should go kaboom
    bob.parse_initial_message(alice_initial_message, alice)


if __name__ == "__main__":
    main()
