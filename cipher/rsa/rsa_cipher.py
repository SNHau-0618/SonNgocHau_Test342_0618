import rsa, os

# Kiểm tra xem thư mục chứa key đã tồn tại chưa
# Nếu chưa tồn tại thì tạo mới thư mục cipher/rsa/keys
if not os.path.exists('cipher/rsa/keys'):
    os.makedirs('cipher/rsa/keys')


# Khai báo class RSACipher để xử lý mã hóa RSA
class RSACipher:

    # Hàm khởi tạo
    def __init__(self):
        pass


    # Hàm tạo cặp khóa RSA
    def generate_keys(self):

        # Tạo public key và private key với độ dài 1024 bit
        (public_key, private_key) = rsa.newkeys(1024)

        # Mở file publicKey.pem để ghi public key
        with open('cipher/rsa/keys/publicKey.pem', 'wb') as p:

            # Lưu public key dưới dạng PEM
            p.write(public_key.save_pkcs1('PEM'))

        # Mở file privateKey.pem để ghi private key
        with open('cipher/rsa/keys/privateKey.pem', 'wb') as p:

            # Lưu private key dưới dạng PEM
            p.write(private_key.save_pkcs1('PEM'))


    # Hàm đọc key từ file
    def load_keys(self):

        # Đọc public key
        with open('cipher/rsa/keys/publicKey.pem', 'rb') as p:

            # Chuyển dữ liệu đọc được thành object PublicKey
            public_key = rsa.PublicKey.load_pkcs1(p.read())

        # Đọc private key
        with open('cipher/rsa/keys/privateKey.pem', 'rb') as p:

            # Chuyển dữ liệu đọc được thành object PrivateKey
            private_key = rsa.PrivateKey.load_pkcs1(p.read())

        # Trả về private key và public key
        return private_key, public_key


    # Hàm mã hóa message bằng RSA
    def encrypt(self, message, key):

        # encode('ascii') chuyển chuỗi sang bytes
        # rsa.encrypt dùng public key để mã hóa
        return rsa.encrypt(message.encode('ascii'), key)


    # Hàm giải mã ciphertext
    def decrypt(self, ciphertext, key):

        try:
            # rsa.decrypt dùng private key để giải mã
            # decode('ascii') chuyển bytes về chuỗi
            return rsa.decrypt(ciphertext, key).decode('ascii')

        except:
            # Nếu lỗi thì trả về False
            return False


    # Hàm ký số (digital signature)
    def sign(self, message, key):

        # Ký message bằng private key
        # SHA-1 là thuật toán băm dùng để tạo chữ ký
        return rsa.sign(message.encode('ascii'), key, 'SHA-256')


    # Hàm xác thực chữ ký số
    def verify(self, message, signature, key):

        try:
            # Kiểm tra chữ ký có hợp lệ không
            # Nếu đúng sẽ trả về 'SHA-1'
            return rsa.verify(message.encode('ascii'),
                              signature,
                              key) == 'SHA-256'

        except:
            # Nếu lỗi hoặc chữ ký sai thì trả về False
            return False