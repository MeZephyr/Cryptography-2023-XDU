import math

if __name__ == '__main__':
    p = 1009
    q = 3643
    n = p * q
    phi_n = (p-1) * (q-1)
    result = 0
    min_res = 9999999999999
    for e in range(1, phi_n):
        if math.gcd(e, phi_n) != 1:
            continue
        num_unconcealed = (math.gcd(e - 1, p - 1) + 1) * (math.gcd(e - 1, q - 1) + 1)
        if num_unconcealed < min_res:
            min_res = num_unconcealed
            result = e
        elif num_unconcealed == min_res:
            result += e
    print("The result is: {}".format(result))
