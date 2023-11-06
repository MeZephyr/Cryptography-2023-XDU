import base64

hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
base64_string = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

# 将hex转换成bytes
bit_string = bytes.fromhex(hex_string)
# 将转换成的bytes进行Base64编码，再用“utf-8”解码，便于比较是否转换正确
base64_string2 = base64.b64encode(bit_string).decode('utf-8')

print(base64_string == base64_string2)
