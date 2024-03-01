from Cryptodome.Util.number import getPrime


class RSA:
    def __init__(self, key_len: int = 100):
        # 初始化RSA对象并生成密钥对
        while True:
            try:
                # 生成两个随机素数 p 和 q
                p, q = getPrime(key_len), getPrime(key_len)
                # 计算 n 作为 p 和 q 的乘积
                n = p * q
                # 计算 "欧拉函数" (et)，即 (p-1) * (q-1)
                et = (p - 1) * (q - 1)
                # 选择公钥指数 e
                e = 3
                # 计算私钥 d，满足 (e * d) % et = 1
                d = pow(e, -1, et)
                break
            except ValueError:
                # 如果生成素数时发生异常，则重新尝试
                continue
        # 保存生成的密钥对
        self.n = n  # 公钥模数
        self.d = d  # 私钥指数
        self.e = e  # 公钥指数

    def encrypt(self, m: bytes) -> int:
        # 加密消息 m
        m = self.bytes_to_num(m)
        c = pow(m, self.e, self.n)
        return c

    def decrypt(self, c: int) -> bytes:
        # 解密密文 c
        m = pow(c, self.d, self.n)
        m = self.num_to_bytes(m)
        return m

    @staticmethod
    def bytes_to_num(seq: bytes) -> int:
        # 将字节数组转换为整数
        return int(seq.hex(), 16)

    @staticmethod
    def num_to_bytes(seq: int) -> bytes:
        # 将整数转换为字节数组
        hex_rep = hex(seq)[2:]
        hex_rep = '0' * (len(hex_rep) % 2) + hex_rep
        return bytes.fromhex(hex_rep)


def main():
    # 示例用法
    rsa_obj = RSA(key_len=1024)
    m = b'MyID:21009200789'
    print('原始消息: {}'.format(m.decode()))

    # 加密消息
    c = rsa_obj.encrypt(m)
    print(f'加密后的密文: {c}')

    # 解密消息
    m_rec = rsa_obj.decrypt(c)
    print('解密后的消息: {}'.format(m_rec.decode()))


if __name__ == '__main__':
    main()
