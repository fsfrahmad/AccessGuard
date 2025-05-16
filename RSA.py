import email
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import base64
import os

class RSACredentialManager:
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
        
    def generate_keys(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
    def save_private_key(self, filename, password=None):
        if self.private_key is None:
            raise ValueError("Private key not generated")
            
        encryption = serialization.NoEncryption()
        if password:
            encryption = serialization.BestAvailableEncryption(password.encode())
            
        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
        
        with open(filename, 'wb') as f:
            f.write(pem)
    
    def save_public_key(self, filename):
        if self.public_key is None:
            raise ValueError("Public key not generated")
            
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(filename, 'wb') as f:
            f.write(pem)
    
    def load_private_key(self, filename, password=None):
        with open(filename, 'rb') as key_file:
            self.private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=password.encode() if password else None,
                backend=default_backend()
            )
        self.public_key = self.private_key.public_key()
    
    def load_public_key(self, filename):
        with open(filename, 'rb') as key_file:
            self.public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
    
    def encrypt_credentials(self, username, email, password, otp):
        if self.public_key is None:
            raise ValueError("Public key not loaded or generated")
            
        username_bytes = username.encode('utf-8')
        email_bytes = email.encode('utf-8')
        password_bytes = password.encode('utf-8')
        otp_bytes = otp.encode('utf-8')
        
        encrypted_username = self.public_key.encrypt(
            username_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        encrypted_email = self.public_key.encrypt(
            email_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        encrypted_password = self.public_key.encrypt(
            password_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        encrypted_otp = self.public_key.encrypt(
            otp_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return (
            base64.b64encode(encrypted_username).decode('utf-8'),
            base64.b64encode(encrypted_email).decode('utf-8'),
            base64.b64encode(encrypted_password).decode('utf-8'),
            base64.b64encode(encrypted_otp).decode('utf-8')
        )
    
    def decrypt_credentials(self, encrypted_username, encrypted_email, encrypted_password, encrypted_otp):
        if self.private_key is None:
            raise ValueError("Private key not loaded or generated")
            
        encrypted_username_bytes = base64.b64decode(encrypted_username)
        encrypted_email_bytes = base64.b64decode(encrypted_email)
        encrypted_password_bytes = base64.b64decode(encrypted_password)
        encrypted_otp_bytes = base64.b64decode(encrypted_otp)
        
        username_bytes = self.private_key.decrypt(
            encrypted_username_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        email_bytes = self.private_key.decrypt(
            encrypted_email_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        password_bytes = self.private_key.decrypt(
            encrypted_password_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        otp_bytes = self.private_key.decrypt(
            encrypted_otp_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return (
            username_bytes.decode('utf-8'),
            email_bytes.decode('utf-8'),
            password_bytes.decode('utf-8'),
            otp_bytes.decode('utf-8')
        )

    def encrypt_aes_key(self, password):
        if self.public_key is None:
            raise ValueError("Public key not loaded or generated")
            
        password_bytes = password.encode('utf-8')
        
        encrypted_password = self.public_key.encrypt(
            password_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return (
            base64.b64encode(encrypted_password).decode('utf-8')
        )

    def decrypt_aes_key(self, encrypted_password):
        if self.private_key is None:
            raise ValueError("Private key not loaded or generated")
            
        encrypted_password_bytes = base64.b64decode(encrypted_password)

        password_bytes = self.private_key.decrypt(
            encrypted_password_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return (
            password_bytes.decode('utf-8')
        )