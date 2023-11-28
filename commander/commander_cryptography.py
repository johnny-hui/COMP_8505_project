import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.dh import DHPublicKey, DHPrivateKey, DHParameters
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def receive_dh_parameters(client_socket: socket.socket):
    """
    Receive Diffie-Hellman parameters from commander.

    @param client_socket:
        The commander socket

    @return parameters:
        A DHParameters object representing the agreed parameters
        for generation of a private/public key pair
    """
    try:
        print("[+] EXCHANGING PARAMETERS: Now receiving Diffie-Hellman parameters from target/victim...")
        serialized_parameter = client_socket.recv(1024)
        parameters = serialization.load_pem_parameters(serialized_parameter, backend=default_backend())

        if parameters is not None:
            print("[+] OPERATION SUCCESSFUL: Diffie-Hellman parameters has been received successfully!")
            client_socket.send("OK".encode())
            return parameters
        else:
            client_socket.send("ERROR".encode())
            return None

    except Exception as e:
        print("[+] EXCHANGE PARAMETERS UNSUCCESSFUL: An error has occurred: {}".format(e))


def generate_keys(parameters: DHParameters):
    """
    Generates private and public keys for a Diffie-Hellman
    Key Exchange.

    @attention: Key Size
        The key size has been reduced from common 2048 to 1024,
        which may reduce the security of the keys.

        This reduction is for faster key generation for
        lower-end systems.

    @return private_key, public_key
        DHPrivateKey and DHPublicKey Objects
    """
    # a) Set DH Parameters (must be agreed upon and same between both cmdr & victim)
    print("[+] GENERATING KEYS: Now generating private and public keys...")

    # b) Generate Private Key (used for generating public key)
    private_key = parameters.generate_private_key()  # => Private Key is a random number

    # c) Generate Public Key (Equation = (Generator ^ private_key) % random prime number)
    public_key = private_key.public_key()
    print("[+] OPERATION SUCCESSFUL: Private and public keys have been successfully generated!")

    return private_key, public_key

def serialize_public_key(public_key: DHPublicKey):
    """
    Serializes the public key for key exchange
    between commander and victim.

    @param public_key:
        A DHPublic Key object representing commander's
        public key

    @return serialized_public_key:
        A byte representation of the commander's public key
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
    Deserializes the victim/target's public key
    from bytes into DHPublicKey object after
    key exchange.

    @param client_public_key_bytes:
        A byte representation of the client's public key

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
        A byte representation of the commander's public key

    @return client_public_key:
        A DHPublic Key object representing victim's public key
    """
    try:
        # a) Send Public Key
        print("[+] KEY EXCHANGE: Now exchanging public keys with target/victim...")
        client_sock.send(serialized_pub_key)

        # b) Await + Receive Status Response
        client_public_key_bytes = client_sock.recv(1024)

        # c) Deserialize the public key
        client_public_key = __deserialize_public_key(client_public_key_bytes)
        print("[+] OPERATION SUCCESSFUL: Target/Victim's public key has been received!")

        return client_public_key

    except Exception as e:
        print("[+] DF KEY EXCHANGE ERROR: An error has occurred during key exchange: {}".format(e))


def key_exchange_receiver(client_sock: socket.socket, serialized_pub_key: bytes):
    """
    Initiates public key exchange (commander awaits)
    between commander and target/victim.

    @attention: Use Case/Scenario
        This is used for when victim is initiating the
        encryption and file transfer

    @param client_sock:
        The client socket

    @param serialized_pub_key:
        A byte representation of the commander's public key

    @return client_public_key:
        A DHPublic Key object representing victim's public key
    """
    try:
        # a) Wait and Receive Public Key (in Serialized (Byte) Form)
        print("[+] KEY EXCHANGE: Now exchanging public keys with target/victim...")
        print("[+] WAITING FOR TARGET/VICTIM: Now waiting for target/victim to send their public key...")
        client_public_key_bytes = client_sock.recv(1024)

        # b) Send Serialized Public Key
        client_sock.send(serialized_pub_key)

        # b) Deserialize the public key
        client_public_key = __deserialize_public_key(client_public_key_bytes)
        print("[+] OPERATION SUCCESSFUL: Target/Victim's public key has been received!")

        return client_public_key

    except Exception as e:
        print("[+] DF KEY EXCHANGE ERROR: An error has occurred during key exchange: {}".format(e))


def generate_shared_secret(private_key: DHPrivateKey, client_public_key: DHPublicKey):
    """
    Given peer's DHPublicKey, carry out the key exchange and
    return shared key as bytes.

    @param private_key:
        The commander's private key

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


def encrypt(file_path: str, shared_key: bytes):
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

        cipher = Cipher(algorithms.AES(shared_key), modes.CFB(b'\0' * 16), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(file_content) + encryptor.finalize()

        print("[+] OPERATION SUCCESSFUL: The data has been successfully encrypted!")
        return encrypted_data

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

        cipher = Cipher(algorithms.AES(shared_key), modes.CFB(b'\0' * 16), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        print("[+] OPERATION SUCCESSFUL: The data has been successfully decrypted!")
        return decrypted_data

    except Exception as e:
        print("[+] FILE DECRYPTION ERROR: An error has occurred while decrypting the data: {}".format(e))
