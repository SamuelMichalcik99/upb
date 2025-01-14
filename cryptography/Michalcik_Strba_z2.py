from flask import Flask, Response, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac
from cryptography.exceptions import InvalidSignature

import os

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'

db = SQLAlchemy(app)

'''
    Tabulka pre pouzivatelov:
    - id: jedinecne id pouzivatela
    - username: meno pouzivatela
    - public_key: verejny kluc pouzivatela

    Poznamka: mozete si lubovolne upravit tabulku podla vlastnych potrieb
'''
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    public_key = db.Column(db.String(120), unique=True, nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

with app.app_context():
    db.create_all()

'''
    API request na generovanie klucoveho paru pre pozuivatela <user>
    - user: meno pouzivatela, pre ktoreho sa ma vygenerovat klucovy par
    - API volanie musi vygenerovat klucovy par pre pozuivatela <user> a verejny kluc ulozit do databazy
    - API volanie musi vratit privatny kluc pouzivatela <user> (v binarnom formate)

    ukazka: curl 127.0.0.1:1337/api/gen/ubp --output ubp.key
'''
@app.route('/api/gen/<user>', methods=['GET'])
def generate_keypair(user):
    # Check if the user already exists
    existing_user = User.query.filter_by(username=user).first()
    if existing_user:
        return jsonify({'error': 'User already exists'}), 400

    # Generate RSA key pair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Serialize the public key to store in the database
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    # Save public key in the database
    new_user = User(username=user, public_key=public_pem)
    db.session.add(new_user)
    db.session.commit()

    # Serialize the private key in DER format (binary)
    private_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,  # Use DER for binary output
        format=serialization.PrivateFormat.PKCS8,  # PKCS8 is a common format for private keys
        encryption_algorithm=serialization.NoEncryption()  # No encryption for the private key
    )

    return Response(private_der, content_type='application/octet-stream')

'''
    API request na zasifrovanie suboru pre pouzivatela <user>
    user: meno pouzivatela, ktoremu sa ma subor zasifrovat
    vstup: subor, ktory sa ma zasifrovat

    ukazka: curl -X POST 127.0.0.1:1337/api/encrypt/upb -H "Content-Type: application/octet-stream" --data-binary @file.pdf --output encrypted.bin
'''
@app.route('/api/encrypt/<user>', methods=['POST'])
def encrypt_file(user):
    # Retrieve user's public key from the database
    user_data = User.query.filter_by(username=user).first()
    if not user_data:
        return jsonify({'error': 'User not found'}), 404

    # Load public key from database
    public_key = serialization.load_pem_public_key(user_data.public_key.encode(), backend=default_backend())

    # Read the file sent by the client in the POST request
    file_data = request.data

    # Generate a random symmetric key (AES key) and an IV (Initialization Vector)
    symmetric_key = os.urandom(32)  # 256-bit AES key
    iv = os.urandom(16)  # AES IV (16 bytes for AES)

    # Encrypt the file with the symmetric key (AES)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_file = encryptor.update(file_data) + encryptor.finalize()

    # Encrypt the symmetric key with the user's public key (RSA)
    encrypted_symmetric_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Concatenate encrypted file, encrypted symmetric key, and IV
    result = encrypted_file + encrypted_symmetric_key + iv

    # Return the concatenated result as a binary stream
    return Response(result, content_type='application/octet-stream')



'''
    API request na desifrovanie
    - vstup: zasifrovany subor ktory sa ma desifrovat a privatny kluc pouzivatela

    ukazka: curl -X POST 127.0.0.1:1337/api/decrypt -F "file=@encypted.bin" -F "key=@upb.key" --output decrypted.pdf
'''
@app.route('/api/decrypt', methods=['POST'])
def decrypt_file():
    # Get the encrypted file and the private key from the request
    encrypted_file_data = request.files['file'].read()
    private_key_file_data = request.files['key'].read()

    # Load the private key in DER format
    private_key = serialization.load_der_private_key(private_key_file_data, password=None, backend=default_backend())

    # Extract last 16 bytes representing IV and 256 bytes representing symetric key from the encrypted file
    iv = encrypted_file_data[-16:]
    encrypted_symmetric_key = encrypted_file_data[-272:-16]
    encrypted_content = encrypted_file_data[:-272]  # The remaining part is the encrypted file content

    # Decrypt the symmetric key using the private RSA key
    symmetric_key = private_key.decrypt(
        encrypted_symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt the file content using the decrypted AES symmetric key and IV
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_file = decryptor.update(encrypted_content) + decryptor.finalize()

    # Return the decrypted file as a binary stream
    return Response(decrypted_file, content_type='application/octet-stream')


'''
    API request na podpisanie dokumentu
    - vstup: subor ktory sa ma podpisat a privatny kluc

    ukazka: curl -X POST 127.0.0.1:1337/api/sign -F "file=@document.pdf" -F "key=@upb.key" --output signature.bin
'''
@app.route('/api/sign', methods=['POST'])
def sign_file():
    # Get the file and the private key from the request
    file_data = request.files['file'].read()
    private_key_file_data = request.files['key'].read()

    # Load the private key
    private_key = serialization.load_der_private_key(private_key_file_data, password=None, backend=default_backend())

    # Generate the digital signature
    signature = private_key.sign(
        file_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Return the digital signature in binary form
    return Response(signature, content_type='application/octet-stream')


'''
    API request na overenie podpisu pre pouzivatela <user>
    - vstup: digitalny podpis a subor

    ukazka: curl -X POST 127.0.0.1:1337/api/verify/upb -F "file=@document.pdf" -F "signature=@signature.bin" --output signature.bin
'''
@app.route('/api/verify/<user>', methods=['POST'])
def verify_signature(user):
    # Get and read the file and the signature from the request
    file_data = request.files['file'].read()
    signature_file_data = request.files['signature'].read()

    # Retrieve user's public key from the database
    user_data = User.query.filter_by(username=user).first()
    if not user_data:
        return jsonify({'error': 'User not found'}), 404

    # Load the public key
    public_key = serialization.load_pem_public_key(user_data.public_key.encode(), backend=default_backend())

    # Verify the signature
    try:
        public_key.verify(
            signature_file_data,
            file_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        verified = True
    except Exception as e:
        verified = False

    return jsonify({'verified': verified})

'''
    API request na zasifrovanie suboru pre pouzivatela <user> (verzia s kontrolou integrity)
    user: meno pouzivatela, ktoremu sa ma subor zasifrovat
    vstup: subor, ktory sa ma zasifrovat

    ukazka: curl -X POST 127.0.0.1:1337/api/encrypt/upb -H "Content-Type: application/octet-stream" --data-binary @file.pdf --output encrypted_file.bin
'''
@app.route('/api/encrypt2/<user>', methods=['POST'])
def encrypt_file2(user):
    # Retrieve user's public key from the database
    user_data = User.query.filter_by(username=user).first()
    if not user_data:
        return jsonify({'error': 'User not found'}), 404

    # Load public key from database
    public_key = serialization.load_pem_public_key(user_data.public_key.encode(), backend=default_backend())

    # Read the file sent by the client in the POST request
    file_data = request.data

    # Generate a random symmetric key (AES key) and an IV (Initialization Vector)
    symmetric_key = os.urandom(32)  # 256-bit AES key
    iv = os.urandom(16)  # AES IV (16 bytes for AES)

    # Encrypt the concatenated data with the symmetric key (AES)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_file = encryptor.update(file_data) + encryptor.finalize()

    # Compute HMAC of the IV and encrypted content
    h = hmac.HMAC(symmetric_key, hashes.SHA256(), backend=default_backend())
    h.update(iv + encrypted_file)
    mac = h.finalize()

    # Encrypt the symmetric key with the user's public key (RSA)
    encrypted_symmetric_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Concatenate encrypted symmetric key, IV, HMAC, and encrypted file
    result = encrypted_symmetric_key + iv + mac + encrypted_file

    # Return the concatenated result as a binary stream
    return Response(result, content_type='application/octet-stream')


'''
    API request na desifrovanie (verzia s kontrolou integrity)
    - vstup: zasifrovany subor ktory sa ma desifrovat a privatny kluc pouzivatela

    ukazka: curl -X POST 127.0.0.1:1337/api/decrypt -F "file=@encypted_file.bin" -F "key=@upb.key" --output decrypted_file.pdf
'''
@app.route('/api/decrypt2', methods=['POST'])
def decrypt_file2():
    # Get the encrypted file and the private key from the request
    encrypted_file_data = request.files['file'].read()
    private_key_file_data = request.files['key'].read()

    # Load the private key in DER format
    private_key = serialization.load_der_private_key(private_key_file_data, password=None, backend=default_backend())

    # Extract components
    encrypted_symmetric_key_size = private_key.key_size // 8  # RSA key size in bytes
    iv_size = 16  # AES IV size
    hmac_size = 32  # HMAC-SHA256 output size

    encrypted_symmetric_key = encrypted_file_data[:encrypted_symmetric_key_size]
    iv = encrypted_file_data[encrypted_symmetric_key_size:encrypted_symmetric_key_size + iv_size]
    mac = encrypted_file_data[encrypted_symmetric_key_size + iv_size:encrypted_symmetric_key_size + iv_size + hmac_size]
    encrypted_content = encrypted_file_data[encrypted_symmetric_key_size + iv_size + hmac_size:]

    # Decrypt the symmetric key using the private RSA key
    try:
        symmetric_key = private_key.decrypt(
            encrypted_symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception:
        return jsonify({'error': 'Failed to decrypt the symmetric key'}), 400

    # Verify HMAC before decrypting the content
    h = hmac.HMAC(symmetric_key, hashes.SHA256(), backend=default_backend())
    h.update(iv + encrypted_content)
    try:
        h.verify(mac)
    except InvalidSignature:
        return jsonify({'error': 'Integrity check failed, HMAC does not match'}), 400

    # Decrypt the encrypted content using the decrypted AES symmetric key and IV
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_file = decryptor.update(encrypted_content) + decryptor.finalize()

    # Return the decrypted file as a binary stream
    return Response(decrypted_file, content_type='application/octet-stream')

if __name__ == '__main__':
    app.run(port=1337)