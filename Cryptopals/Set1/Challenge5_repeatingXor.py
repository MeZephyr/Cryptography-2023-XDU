plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
key = "ICE"
target_string = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"


def repeating_xor(text: bytes, key: bytes) -> bytes:
    quotient, remainder = divmod(len(text), len(key))
    key_extend = bytes(key * quotient + key[:remainder])
    return bytes([x ^ y for x, y in zip(text, key_extend)])


byte_string = plaintext.encode()
byte_Key = key.encode()

ciphertext = repeating_xor(byte_string, byte_Key)

print(ciphertext.hex() == target_string)
