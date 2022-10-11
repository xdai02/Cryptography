import re


def generate_key(plaintext, key):
    n = len(plaintext) - len(key)
    for i in range(n): 
        key += key[i % len(key)]
    return key


def encrypt(plaintext, key):
    # remove all non-alphabetic characters
    plaintext = re.sub("[ \n\r]", '', plaintext).upper()
    key = generate_key(plaintext, key)

    ciphertext = ""
    for i in range(len(plaintext)):
        ciphertext += chr((ord(plaintext[i]) + ord(key[i])) % 26 + 65)
    return ciphertext


def decrypt(ciphertext, key):
    # remove all non-alphabetic characters
    ciphertext = re.sub("[ \n\r]", '', ciphertext).upper()
    key = generate_key(ciphertext, key)

    plaintext = ""
    for i in range(len(ciphertext)):
        plaintext += chr((ord(ciphertext[i]) - ord(key[i])) % 26 + 65)
    return plaintext


def main():
    print("Caesar Cipher")
    print("1. Encryption")
    print("2. Decryption")
    choice = int(input("Select << "))

    if choice == 1:
        plaintext = input("Plaintext: ")
        key = input("Key: ")
        ciphertext = encrypt(plaintext, key)
        print("Ciphertext:", ciphertext)
    elif choice == 2:
        ciphertext = input("Ciphertext: ")
        key = input("Key: ")
        plaintext = decrypt(ciphertext, key)
        print("Plaintext:", plaintext)


if __name__ == "__main__":
    main()