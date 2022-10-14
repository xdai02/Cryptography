def gcd(a, b):
    while b != 0:
        remainder = a % b
        a = b
        b = remainder
    return a


def euclid_gcd(a, b):
    if b == 0:
        return a
    return gcd(b, a % b)


def lcm(a, b):
    return a * b // gcd(a, b)


def main():
    a, b = map(int, input("Enter two integers: ").split())
    print("gcd({0}, {1}) = {2}".format(a, b, gcd(a, b)))
    print("euclid_gcd({0}, {1}) = {2}".format(a, b, euclid_gcd(a, b)))
    print("lcm({0}, {1}) = {2}".format(a, b, lcm(a, b)))


if __name__ == "__main__":
    main()