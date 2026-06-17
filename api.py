from flask import Flask, request, jsonify
from cipher.rsa import RSACipher


# Khởi tạo ứng dụng Flask
app = Flask(__name__)


# ================= RSA CIPHER ALGORITHM =================

# Tạo object RSA Cipher
rsa_cipher = RSACipher()


# =========================================================
# API GENERATE KEYS
# =========================================================

@app.route('/api/rsa/generate_keys', methods=['GET'])
def rsa_generate_keys():

    # Tạo public key và private key
    rsa_cipher.generate_keys()

    # Trả kết quả JSON
    return jsonify({
        'message': 'Keys generated successfully'
    })


# =========================================================
# API ENCRYPT
# =========================================================

@app.route('/api/rsa/encrypt', methods=['POST'])
def rsa_encrypt():

    # Lấy dữ liệu JSON client gửi lên
    data = request.json

    # Lấy message cần mã hóa
    message = data['message']

    # Lấy loại key
    key_type = data['key_type']

    # Đọc key từ file
    private_key, public_key = rsa_cipher.load_keys()

    # Chọn key
    if key_type == 'public':

        # Dùng public key
        key = public_key

    elif key_type == 'private':

        # Dùng private key
        key = private_key

    else:

        # Báo lỗi nếu key type không hợp lệ
        return jsonify({
            'error': 'Invalid key type'
        })

    # Mã hóa message
    encrypted_message = rsa_cipher.encrypt(message, key)

    # Chuyển bytes sang hex
    encrypted_hex = encrypted_message.hex()

    # Trả dữ liệu về client
    return jsonify({
        'encrypted_message': encrypted_hex
    })


# =========================================================
# API DECRYPT
# =========================================================

@app.route('/api/rsa/decrypt', methods=['POST'])
def rsa_decrypt():

    # Lấy dữ liệu JSON
    data = request.json

    # Lấy ciphertext dạng hex
    ciphertext_hex = data['ciphertext']

    # Lấy loại key
    key_type = data['key_type']

    # Load key từ file
    private_key, public_key = rsa_cipher.load_keys()

    # Chọn key
    if key_type == 'public':

        # Dùng public key
        key = public_key

    elif key_type == 'private':

        # Dùng private key
        key = private_key

    else:

        # Nếu key type sai
        return jsonify({
            'error': 'Invalid key type'
        })

    # Chuyển hex thành bytes
    ciphertext = bytes.fromhex(ciphertext_hex)

    # Giải mã dữ liệu
    decrypted_message = rsa_cipher.decrypt(ciphertext, key)

    # Trả kết quả
    return jsonify({
        'decrypted_message': decrypted_message
    })


# =========================================================
# API SIGN MESSAGE
# =========================================================

@app.route('/api/rsa/sign', methods=['POST'])
def rsa_sign_message():

    # Lấy dữ liệu JSON
    data = request.json

    # Lấy message
    message = data['message']

    # Load key
    private_key, _ = rsa_cipher.load_keys()

    # Ký số bằng private key
    signature = rsa_cipher.sign(message, private_key)

    # Chuyển signature sang hex
    signature_hex = signature.hex()

    # Trả kết quả
    return jsonify({
        'signature': signature_hex
    })


# =========================================================
# API VERIFY SIGNATURE
# =========================================================

@app.route('/api/rsa/verify', methods=['POST'])
def rsa_verify_signature():

    # Lấy dữ liệu JSON
    data = request.json

    # Lấy message
    message = data['message']

    # Lấy chữ ký dạng hex
    signature_hex = data['signature']

    # Load public key
    _, public_key = rsa_cipher.load_keys()

    # Chuyển hex sang bytes
    signature = bytes.fromhex(signature_hex)

    # Kiểm tra chữ ký
    is_verified = rsa_cipher.verify(
        message,
        signature,
        public_key
    )

    # Trả kết quả xác thực
    return jsonify({
        'is_verified': is_verified
    })

# =========================================================
# MAIN FUNCTION
# =========================================================

if __name__ == '__main__':

    # Chạy Flask Server
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True
    )