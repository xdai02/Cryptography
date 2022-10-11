def encrypt(plaintext, shift=3):
    shift %= 26
    ciphertext = ""

    for c in plaintext:
        if not c.isalpha():
            ciphertext += c
            continue
        if c.isupper():
            ciphertext += chr((ord(c) + shift - 65) % 26 + 65)
        else:
            ciphertext += chr((ord(c) + shift - 97) % 26 + 97)

    return ciphertext


def decrypt(ciphertext, shift=3):
    plaintext = ""

    for c in ciphertext:
        if not c.isalpha():
            plaintext += c
            continue
        if c.isupper():
            plaintext += chr((ord(c) - shift - 65) % 26 + 65)
        else:
            plaintext += chr((ord(c) - shift - 97) % 26 + 97)

    return plaintext


def main():
    print("Caesar Cipher")
    print("1. Encryption")
    print("2. Decryption")
    choice = int(input("Select << "))

    if choice == 1:
        plaintext = input("Plaintext: ")
        shift = int(input("Shift: "))
        ciphertext = encrypt(plaintext, shift)
        print("Ciphertext: ", ciphertext)
    elif choice == 2:
        ciphertext = input("Ciphertext: ")
        for shift in range(1, 26):
            plaintext = decrypt(ciphertext, shift)
            print("Plaintext (shift=%d): %s" % (shift, plaintext))


if __name__ == "__main__":
    main()