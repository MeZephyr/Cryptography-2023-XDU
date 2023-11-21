import re
import secrets
from Cryptodome.Cipher import AES  # pip install pycryptodomex

global user_id


# ECB加密
def AES_ECB_encrypt(plaintext: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(PKCS7_pad(plaintext, AES.block_size))
    return ciphertext


# PKCS7填充
def PKCS7_pad(plaintext: bytes, block_size: int) -> bytes:
    padding_byte = block_size - len(plaintext) % block_size
    plaintext += padding_byte.to_bytes(1, "big") * padding_byte
    return plaintext


# 判断是否为PKCS7填充
def is_PKCS7_padded(text: bytes):
    # text[-x] 表示从字符串的末尾往前数第 x 个字符。
    # text[-x:] 表示从上述位置开始，取到字符串的末尾（包括第 x 个字符），形成一个子串。
    padding = text[-text[-1]:]
    for byte in padding:
        if not byte == text[-1]:
            return False
    return True


# 去除PKCS7填充
def PKCS7_trim(text: bytes):
    if is_PKCS7_padded(text):
        pad_length = text[-1]
        # text[:-x] 表示从字符串的开头取子串，直到倒数第 x 个字符之前（不包括倒数第 x 个字符）。
        return text[:-pad_length]
    else:
        return text


# 生成一个随机的16字节的key
# 比 os.urandom(n) 更为安全
def generate_key() -> bytes:
    return secrets.token_bytes(16)


key = generate_key()


# 分割字符串或合成字符串
def parser(user_string, symbol: bool):
    if symbol:
        parsed = {dict_key: val for dict_key, val in (item.split("=") for item in user_string.split("&"))}
        return parsed
    else:
        parsed = "&".join([f"{dict_key}={val}" for dict_key, val in user_string.items()])
        return parsed


# 生成一个profile
def profile_for(email: str) -> dict:
    global user_id
    # 使用正则表达式去除email中的&和=
    user_info = re.sub("&|=", "", email)
    # 设定cookie中的role为user
    cookie = f"email={user_info}&uid={user_id}&role=user"
    user_id += 1
    return parser(cookie, True)


# 加密profile
def encrypt_profile(profile: dict) -> bytes:
    plain_cookie = parser(profile, False).encode()
    cipher_cookie = AES_ECB_encrypt(plain_cookie, key)
    return cipher_cookie


# 解密profile
def decrypt_profile(cipher_cookie: bytes, key: bytes):
    plain_cookie = AES.new(key, AES.MODE_ECB).decrypt(cipher_cookie)
    plain_cookie = PKCS7_trim(plain_cookie)
    cookie = plain_cookie.decode()
    return cookie, parser(cookie, True)


# 生成一个admin的profile
def create_admin_profile():

    cookie_parts = f"email=@outlook.com&uid={user_id}&role="
    user_name = 'A' * (AES.block_size - len(cookie_parts) % AES.block_size)
    email = user_name + "@outlook.com"
    cipher_cookie = encrypt_profile(profile_for(email))

    cookie_param = "email="
    hacker_mail = 'A' * (AES.block_size - len(cookie_param) % AES.block_size)
    value = PKCS7_pad(b"admin", AES.block_size)
    hacker_mail += value.decode()
    cipher_cookie2 = encrypt_profile(profile_for(hacker_mail))

    block1 = cipher_cookie[:-AES.block_size]
    block2 = cipher_cookie2[AES.block_size:AES.block_size * 2]
    cipherBlock = block1 + block2

    cookie, dictionary = decrypt_profile(cipherBlock, key)
    print("cookie:", cookie)
    print("dictionary:", dictionary)


if __name__ == "__main__":
    user_id = 0
    create_admin_profile()
