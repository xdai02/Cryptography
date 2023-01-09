import hashlib


def md5(plaintext):
    h = hashlib.md5()
    h.update(plaintext.encode())
    return h.hexdigest()


def sha256(plaintext):
    h = hashlib.sha256()
    h.update(plaintext.encode())
    return h.hexdigest()


def sha512(plaintext):
    h = hashlib.sha512()
    h.update(plaintext.encode())
    return h.hexdigest()


def main():
    plaintext = "Hello World"

    print("MD5: ", md5(plaintext))
    print("SHA256: ", sha256(plaintext))
    print("SHA512: ", sha512(plaintext))


if __name__ == "__main__":
    main()
