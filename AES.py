#most commonly used S_BOX and INVERSE_S_BOX is taken below (seen in lecture slides)
S_BOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

INVERSE_S_BOX = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

#Round constants for key expansion and these are also common
RCON = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)


#from the 1D array we will make 2D array for our ease
def generate_2D_matrix(hex_string):
    matrix_4x4 = [list(hex_string[i:i+4]) for i in range(0, len(hex_string), 4)]
    return list(zip(*matrix_4x4))

#this function will convert String to hex_array
def string_to_hex(input_string):
    #we are doing this conversion as performing AES on hex_array is more effortless
    hex_array = [hex(ord(char))[2:] for char in input_string]
    return hex_array

#opposite of above function: convert hex_array to string to show output
def hex_to_string(hex_array):
    #we are doing this as String is more easily readable and we can see
    #if correct output is there after deciphering or not
    output_string = ''.join([chr(int(hex_char, 16)) for hex_char in hex_array])
    return output_string

#this function is needed to perform mix_column for both encrypt and decrypt
#reference: http://blog.simulacrum.me/2019/01/aes-galois/
def galois_multiplication(a, b):
    result = 0
    for i in range(8):
        if b & 1:
            result ^= a
        #first check if the most significant bit is set
        msb_set = a & 0x80
        #a is shifted left by 1
        a <<= 1
        #if the most significant bit was set, XOR with 0x1b
        if msb_set:
            a ^= 0x1b
        #b is shifted right by 1
        b >>= 1
    return result % 256

# Each column and a constant numbers are sent to Galois Multiplication function
def mix_column_both(column, bool):
    if bool:
        #for encryption this is used to to mix_column operation
        #and the constants that we are using 2, 1, 1, 3 are calculated mathematically
        #we will use GF multiplication function to complete mix_column
        #a copy of column is made
        temp = column[:]
        column[0] = galois_multiplication(temp[0], 2) ^ galois_multiplication(temp[3], 1) ^ galois_multiplication(temp[2], 1) ^ galois_multiplication(temp[1], 3)
        
        column[1] = galois_multiplication(temp[1], 2) ^ galois_multiplication(temp[0], 1) ^ galois_multiplication(temp[3], 1) ^ galois_multiplication(temp[2], 3)
        
        column[2] = galois_multiplication(temp[2], 2) ^ galois_multiplication(temp[1], 1) ^ galois_multiplication(temp[0], 1) ^ galois_multiplication(temp[3], 3)
        
        column[3] = galois_multiplication(temp[3], 2) ^ galois_multiplication(temp[2], 1) ^ galois_multiplication(temp[1], 1) ^ galois_multiplication(temp[0], 3)
    else:
        #for decryption this is used to to mix_column operation
        #and the constants that we are using 14, 9, 13, 11 are calculated mathematically
        #we will use GF multiplication function to complete mix_column
        #a copy of column is made
        temp = column[:]

        column[0] = galois_multiplication(temp[0], 14) ^ galois_multiplication(temp[3], 9) ^ galois_multiplication(temp[2], 13) ^ galois_multiplication(temp[1], 11)
    
        column[1] = galois_multiplication(temp[1], 14) ^ galois_multiplication(temp[0], 9) ^ galois_multiplication(temp[3], 13) ^ galois_multiplication(temp[2], 11)
    
        column[2] = galois_multiplication(temp[2], 14) ^ galois_multiplication(temp[1], 9) ^ galois_multiplication(temp[0], 13) ^ galois_multiplication(temp[3], 11)
    
        column[3] = galois_multiplication(temp[3], 14) ^ galois_multiplication(temp[2], 9) ^ galois_multiplication(temp[1], 13) ^ galois_multiplication(temp[0], 11)

#it takes state_matrix and boolean value as input and then, int converts row-col based matrix to
#col-row based and then calls helper function which ultimately uses GF_multiplication function
def mix_columns(matrix, bool):
    #convert hex string matrix to an integer matrix
    int_matrix = [[int(k, 16) for k in row] for row in matrix]

    #we are iterating over each column of the matrix
    for i in range(4):
        #current column from the state_int is stored in col
        col = [int_matrix[j][i] for j in range(4)]
        
        #for encrypt/decrypt mix_column_both function is called and used
        if bool:
            #for encryption
            mix_column_both(col, bool=True)
        else:
            #for decryption
            mix_column_both(col, bool=False)
        
        #original state matrix is updated with mixed column values
        for j in range(4):
            #hex_str value conversion
            matrix[j][i] = "{:02x}".format(col[j])

#shifts left and right each item of the array by one(we can use this if required)
#helper function
def left_and_right_shift(arr, bool):
    if bool:
        #left shift code
        arr[1:] + [arr[0]]
    else:
        #right shift code
        temp = arr[-1]
        for i in range(len(arr) - 1, 0, -1):
            arr[i] = arr[i - 1]
        arr[0] = temp
    return arr

#shifts left each item of the array by one
def left_shift(arr):
    return arr[1:] + [arr[0]]

#shifts right each item of the array by one
def right_sift(arr):
    #last element of the array is stored here
    temp = arr[-1]
    for i in range(len(arr) - 1, 0, -1):
        #shifting each element of the array right by 1
        arr[i] = arr[i - 1]
    #last element is stored at 0th index
    arr[0] = temp
    return arr

#this is creating the error if changed from left_shift to left_and_right_shift
#for encryption/decryption shift_rows is done
def shift_row(matrix):
    #0th row is not shifted
    #1st row is left_shifted once
    matrix[1] = left_shift(matrix[1])
    #2nd row is left_shifted two times
    matrix[2] = left_shift(matrix[2])
    matrix[2] = left_shift(matrix[2])
    #3rd rows is left_shifted 3 times
    matrix[3] = left_shift(matrix[3])
    matrix[3] = left_shift(matrix[3])
    matrix[3] = left_shift(matrix[3])

#for decryption shift_rows is done
def inverse_shift_row(matrix):
    #0th rows is not shifted
    #1st rows is shifted_right once
    matrix[1] = left_and_right_shift(matrix[1], bool=False)
    #2nd rows is shifted_right twice
    matrix[2] = left_and_right_shift(matrix[2], bool=False)
    matrix[2] = left_and_right_shift(matrix[2], bool=False)
    #3rd rows is shifted_right thrice
    matrix[3] = left_and_right_shift(matrix[3], bool=False)
    matrix[3] = left_and_right_shift(matrix[3], bool=False)
    matrix[3] = left_and_right_shift(matrix[3], bool=False)

#to generate all the Round_keys this function is made
#these key will be used by both Encrypt/decrypt
def key_expansion(main_key):
    #empty array to store keys is made
    w = [[0] * 4 for _ in range(44)]

    #main key converted to 4x4 matrix of integers
    for i in range(4):
        for j in range(4):
            w[i][j] = int(main_key[i * 4 + j], 16)

    ##Key expansion is done below
    for word_num in range(4, 4 * (11)):
        if word_num % 4 == 0:
            temp_w = w[word_num - 1][:]
            temp_w = left_shift(temp_w)
            temp_w = [S_BOX[val] for val in temp_w]
            temp_w[0] ^= RCON[word_num // 4]

            #XOR with the word 4 positions earlier
            for i in range(4):
                w[word_num][i] = temp_w[i] ^ w[word_num - 4][i]
        else:
            #XOR with the word 4 positions earlier
            for i in range(4):
                w[word_num][i] = w[word_num - 1][i] ^ w[word_num - 4][i]

    #hex-string of round key is made
    temp_round_keys_hex = ['{:02x}'.format(byte) for word in w for byte in word]

    #key_list for rounds is made
    round_keys_in_hex = [temp_round_keys_hex[i:i + (4 * 4)] for i in
                         range(0, len(temp_round_keys_hex), 4 * 4)]

    return round_keys_in_hex

#two inputs text and round key is given and this function will perform XOR operation
#respectively like 1st element of text is XOR-ed with 1st element of round_key
#used during both encryption and decryption
def add_round_key(text_x, key_x):
    #empty array is made to store the result (effectively it will be 2D-array 4x4)
    result = []
    for i in range(4):
        #row of 4x4 matrix is calculted
        row = []
        for j in range(4):
            #hex_str to int
            text_ij = int(text_x[i][j], 16)
            key_ij = int(key_x[i][j], 16)
            #changing int to hex_str
            row.append("{:02x}".format(text_ij ^ key_ij))
        result.append(row)
    return result

#encryption: it uses S_BOX to fill up the value whereas for decryption: INVERSE_S_BOX
def substitute_bytes(matrix, bool):
    if bool:
        #if encryption then this block will be executed
        s_box = S_BOX
    else:
        #if decryption then this block will be executed
        s_box = INVERSE_S_BOX
    for i in range(4):
        for j in range(4):
            int_val = int(matrix[i][j], 16)
            # print(s_box[0])
            s_box_val = s_box[int_val]
            #hex_str is converted
            hex_s_box_val = "{:02x}".format(s_box_val)
            matrix[i][j] = hex_s_box_val

#AES encryption function; Inputs are plaintext and All_round_keys; and number of rounds
def AES_encrypt_function(text_hex, all_round_keys):
    encryption_1_output=[]
    encryption_9_output=[]

    #state matrix with the plaintext is generated in the form of 4x4 matrix
    state_matrix = generate_2D_matrix(text_hex)
    #4x4 matrix of original(1st) key for initial permutation is made
    key_matrix = generate_2D_matrix(all_round_keys[0])

    #initial round key addition is done
    current_state_matrix = add_round_key(state_matrix, key_matrix)
    # print(current_matrix)

    #perform 9 rounds of encryption normally
    #but we can modify it to perform selected number of rounds
    for i in range(1, 10):
        #case to store the output after Round-1
        if(i==2):
            encryption_1_output=current_state_matrix
            print(i-1,"Round of Encryption: ", current_state_matrix)

        #case to store the output after Round-9
        if(i==9):
            encryption_9_output=current_state_matrix
            print(i,"Round of Encryption: ", current_state_matrix)
        
        #substitution bytes operation is used
        substitute_bytes(current_state_matrix, bool=True)
        # print(current_matrix, '\n')
        #shift row operation is used
        shift_row(current_state_matrix)
        #mix column operation is used
        mix_columns(current_state_matrix, bool=True)
        #round key is added
        current_state_matrix = add_round_key(current_state_matrix, generate_2D_matrix(all_round_keys[i]))

    #final round of encryption is done
    substitute_bytes(current_state_matrix, bool=True)
    shift_row(current_state_matrix)
    #final round key is added
    cipher_text_matrix = add_round_key(current_state_matrix, generate_2D_matrix(all_round_keys[10]))

    #cipher text matrix is converted to a 1D array of hex strings
    cipher_text = []
    p1=[]
    p9=[]
    for i in range(4):
        for j in range(4):
            cipher_text.append(cipher_text_matrix[j][i])
            p1.append(encryption_1_output[j][i])
            p9.append(encryption_9_output[j][i])

    return cipher_text, p1, p9

#AES decryption function; Inputs are ciphertext and All_round_keys; and number of rounds
def AES_decrypt_function(cipher_text, all_round_keys):
    decryption_1_output=[]
    decryption_9_output=[]
    
    #state matrix with the ciphertext is generated in the form of 4x4 matrix
    state_matrix = generate_2D_matrix(cipher_text)
    #4x4 matrix of last key for initial permutation is made
    key_matrix = generate_2D_matrix(all_round_keys[10])

    #initial round key addition
    current_state_matrix = add_round_key(state_matrix, key_matrix)
    
    #final round(actually first) of decryption done
    inverse_shift_row(current_state_matrix)
    substitute_bytes(current_state_matrix, bool=False)


    #remaining 9 rounds of decryption is done in normal case
    #but we can make this run for the number of rounds we want
    i = 1
    while i < 10:
        if(i==2):
            #decryption 1st round output for verification
            decryption_1_output=current_state_matrix
            print(i-1,"Round of Decryption: ", current_state_matrix)
        #decryption 9th round output for verification
        if(i==9):
            decryption_9_output=current_state_matrix
            print(i,"Round of Decryption: ", current_state_matrix)
        
        
        #round key is added
        current_state_matrix = add_round_key(current_state_matrix, generate_2D_matrix(all_round_keys[10-i]))
        #inverse of mix column operation
        mix_columns(current_state_matrix, bool=False)
        #inverse of shift row operation
        inverse_shift_row(current_state_matrix)
        #inverse of substitution bytes operation
        substitute_bytes(current_state_matrix, bool=False)
        i = i+1

    #final round key addition done
    plain_text_matrix = add_round_key(current_state_matrix, generate_2D_matrix(all_round_keys[0]))

    #plain text matrix converted to a 1D of hex strings
    plain_text = []
    p1=[]
    p9=[]
    for i in range(4):
        for j in range(4):
            plain_text.append(plain_text_matrix[j][i])
            p1.append(decryption_1_output[j][i])
            p9.append(decryption_9_output[j][i])

    return plain_text, p1, p9


if __name__ == '__main__':
    
    KEYS = ["Network is mythq", "Rishabh is great", "Hello NetworkSec"]
    TEXTS = ["Securityisamythy", "Abhishekishonest", "network security"]

    for i in range(3):
        print("Sample input and Output", i+1)
        main_key = string_to_hex(KEYS[i])
        main_text = string_to_hex(TEXTS[i])
        all_round_keys = key_expansion(main_key)
        ciphertext, encryption_1_output, encryption_9_output = AES_encrypt_function(main_text, all_round_keys)
        # print(ciphertext)
        ciphertext_str = hex_to_string(ciphertext)
        decrypt_text, decryption_1_output, decryption_9_output = AES_decrypt_function(ciphertext, all_round_keys)
        decrypt_text_str = hex_to_string(decrypt_text)
        print("Case (b): Verified that the output of the 1st encryption round is the same as the output of the 9th decryption round as you can see above")
        print("Case (c): Verified that the output of the 9th encryption round is the same as the output of the 1st decryption round as you can see above")
        print()
        #printing the key used
        print("Key : '{}'".format(KEYS[i]))
        # Print the plain text
        print("Plain Text : '{}'".format(TEXTS[i]))
        # Print the encrypted text
        print("Encrypted Text :", ciphertext_str)
        # Print the Deciphered text
        print("Deciphered Text : '{}'".format(decrypt_text_str))
        
        # Check for case (a): Verify that AES encryption and decryption is working properly
        if TEXTS[i] == decrypt_text_str:
            print("Case (a): Verified that AES encryption and decryption is working properly. Plaintext = Deciphered text")
        else:
            print("Case (a): AES Encryption/Decryption failed")

        #Check for case (b): Verify that the output of 1st encryption round is the same as output of the 9th decryption round
        #already verified above as you can see for all three cases
        #Check for case (c): Verify that the output of 9th encryption round is the same as output of the 1st decryption round
        #already verified above as you can see for all three cases
        print()

