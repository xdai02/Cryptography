def hex2dec(hex):
    return int(hex, 16)


def dec2hex(dec):
    return hex(dec)[2:].zfill(2)


def dec2bin(dec):
    return bin(dec)[2:].zfill(8)


def bin2dec(bin):
    return int(bin, 2)


def bin2hex(bin):
    return dec2hex(int(bin, 2))


def expand(key, bits):
    """
        Expand the key to the right size
    """
    length = len(key)
    diff = bits // 4 - length

    # cut the key to the right size
    if diff < 0:
        return key[:bits // 4]
    return '0' * diff + key


def get_sub_matrix(matrix, start_row, end_row, start_col, end_col):
    return [row[start_row:end_row+1] for row in matrix[start_col:end_col+1]]


def get_matrix_col(matrix, col):
    return [matrix[i][col] for i in range(len(matrix))]


def shift_left(lst, n):
    return lst[n:] + lst[:n]


class AES:
    __BITS = 128      # AES-128
    __ROUND = 10      # 10 round for 128-bit key

    __S_BOX = [
        [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
        [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
        [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
        [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
        [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
        [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
        [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
        [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
        [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
        [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
        [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
        [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
        [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
        [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
        [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
        [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16],
    ]

    __ROUND_CONSTANT = [
        [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36],
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    ]

    __PREDEFINED_MATRIX = [
        [0x02, 0x03, 0x01, 0x01],
        [0x01, 0x02, 0x03, 0x01],
        [0x01, 0x01, 0x02, 0x03],
        [0x03, 0x01, 0x01, 0x02],
    ]

    def __init__(self, key):
        key = expand(key, self.__BITS)
        self.__round_keys = self.__expand_key(key)

    def __expand_key(self, key):
        row = 4
        col = 4 * (self.__ROUND + 1)

        matrix = [[0x00 for _ in range(col)] for _ in range(row)]

        # fill the first 4 columns with the initial key
        for j in range(4):
            for i in range(4):
                matrix[i][j] = hex2dec(key[8 * j + 2 * i: 8 * j + 2 * i + 2])

        # fill the rest of the columns for each round key
        for j in range(4, col):
            # W[j] = W[j-4] XOR W[j-1]
            if j % 4 != 0:
                for i in range(4):
                    matrix[i][j] = matrix[i][j - 4] ^ matrix[i][j - 1]
            # W[j] = W[j-4] XOR T(W[j-1])
            else:
                key = get_matrix_col(matrix, j - 1)

                # 1-byte left circular shift
                key = shift_left(key, 1)

                # substitute each byte with the S-box
                for i in range(4):
                    byte = dec2hex(key[i])
                    row = hex2dec(byte[0])
                    col = hex2dec(byte[1])
                    key[i] = self.__S_BOX[row][col]

                # XOR with the round constant
                round_contant = get_matrix_col(self.__ROUND_CONSTANT, j // 4 - 1)
                for i in range(4):
                    matrix[i][j] = matrix[i][j - 4] ^ key[i] ^ round_contant[i]

        # convert the matrix to a list of round keys
        round_keys = []
        for i in range(self.__ROUND + 1):
            round_key = get_sub_matrix(matrix, 4 * i, 4 * i + 3, 0, 3)
            round_keys.append(round_key)
        return round_keys

    def encrypt(self, plaintext):
        # convert the plaintext to a matrix
        matrix = []
        for j in range(4):
            row = []
            for i in range(4):
                row.append(hex2dec(plaintext[8 * i + 2 * j: 8 * i + 2 * j + 2]))
            matrix.append(row)

        # Initial round
        matrix = self.__initial_round(matrix)

        for round in range(1, self.__ROUND + 1):
            # SubBytes
            matrix = self.__sub_bytes(matrix)

            # ShiftRows
            matrix = self.__shift_rows(matrix)

            # MixColumns
            if round != self.__ROUND:
                matrix = self.__mix_columns(matrix)

            # AddRoundKey
            matrix = self.__add_round_key(matrix, round)
        
        ciphertext = ''.join([dec2hex(matrix[j][i]) for i in range(4) for j in range(4)])
        return ciphertext
    
    def __initial_round(self, matrix):
        for i in range(4):
            for j in range(4):
                matrix[i][j] ^= self.__round_keys[0][i][j]
        return matrix

    def __sub_bytes(self, matrix):
        for i in range(4):
            for j in range(4):
                byte = dec2hex(matrix[i][j])
                row = hex2dec(byte[0])
                col = hex2dec(byte[1])
                matrix[i][j] = self.__S_BOX[row][col]
        return matrix

    def __shift_rows(self, matrix):
        for i in range(4):
            matrix[i] = shift_left(matrix[i], i)
        return matrix

    def __mix_columns(self, matrix):
        A = self.__PREDEFINED_MATRIX
        B = matrix
        C = [[0x00] * 4 for _ in range(4)]

        for i in range(4):
            for j in range(4):
                for k in range(4):
                    # 0x01 * a7a6a5a4a3a2a1a0
                    if A[i][k] == 0x01:
                        C[i][j] ^= B[k][j]
                    # 0x02 * a7a6a5a4a3a2a1a0
                    elif A[i][k] == 0x02:
                        # a7 = 0
                        if dec2bin(B[k][j])[0] == "0":
                            # result = (a6a5a4a3a2a1a0)0
                            C[i][j] ^= bin2dec(dec2bin(B[k][j]) + "0")
                        # a7 = 1
                        else:
                            # result = (a6a5a4a3a2a1a0)0 XOR (00011011)
                            C[i][j] ^= bin2dec(dec2bin(B[k][j]) + "0") ^ 0x1b
                    # 0x03 * a7a6a5a4a3a2a1a0
                    else:
                        # result = [(00000010) * (a7a6a5a4a3a2a1a0)] XOR (a7a6a5a4a3a2a1a0)
                        # a7 = 0
                        if dec2bin(B[k][j])[0] == "0":
                            temp = bin2dec(dec2bin(B[k][j]) + "0")
                        # a7 = 1
                        else:
                            # result = (a6a5a4a3a2a1a0)0 XOR (00011011)
                            temp = bin2dec(dec2bin(B[k][j]) + "0") ^ 0x1b
                        C[i][j] ^= temp ^ B[k][j]
                    
                    binary = dec2bin(C[i][j])
                    if len(binary) > 8:
                        C[i][j] = bin2dec(binary[1:])

        return C

    def __add_round_key(self, matrix, round):
        for i in range(4):
            for j in range(4):
                matrix[i][j] ^= self.__round_keys[round][i][j]
        return matrix


def main():
    plaintext = "3243f6a8885a308d313198a2e0370734"
    aes = AES(key="2b7e151628aed2a6abf7158809cf4f3c")
    ciphertext = aes.encrypt(plaintext)
    print("Plaintext:", plaintext)
    print("Ciphertext:", ciphertext)


if __name__ == "__main__":
    main()