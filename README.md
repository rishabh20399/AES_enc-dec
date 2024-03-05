Funtions:
 1. generate_2D_matrix(hex_string)
 2. string_to_hex(input_string)
 3. hex_to_string(hex_array)
 4. galois_multiplication(a, b)
 5. mix_column_both(column, bool)
 6. mix_columns(matrix, bool)
 7. left_and_right_shift(arr, bool)
 8. left_shift(arr) and right_shift(arr)
 9. shift_row(matrix) and inverse_shift_row(matrix)
 10. key_expansion(main_key)
 11. add_round_key(text_x, key_x)
 12. substitute_bytes(matrix, bool)
 13. AES_encrypt_function(text_hex, all_round_keys)
 14. AES_decrypt_function(cipher_text, all_round_keys).

     
 Explanations:
 
 1. generate_2D_matrix(hex_string)
 ● Ahexstring is the input for this function.
 ● Thehexstring is transformed into a list of lists, with each inner list standing
 in for an individual row of the matrix, to create the 4x4 matrix.
 ● Finally, zip( *matrix_4x4) is used to return the transposed matrix, effectively
 converting row-major ordering to column major ordering.
 
 2. string_to_hex(input_string)
 ● Astring is the input for this function.
 ● Using the ord( char) and hex() functions, it transforms each character in the input
 string into the corresponding representation of a HEXAdecimal number.
 ● Hexadecimal representations are returned after being stored in a list.
 
 3. hex_to_string(hex_array)
 ● Alist of hexadecimal strings is entered into this function.
 ● Using int( hex_char, 16) to obtain the ASCII value and chr(), it iterates over each
 hemidecimal string before returning it to its corresponding character.
 ● Theoriginal string is created by adding the characters together, and it is then
 returned.

4. galois_multiplication(a, b)(http://blog.simulacrum.me/2019/01/aes-galois/)
 ● TheAESencryption algorithm's Galois Field( GF) multiplication of the numbers a
 and b is carried out by this function.
 ● It performs conditional XOR operations on a based on the bits of b while it
 iterates over each bit.
 ● TheGF(2^8) field property is maintained by performing an XOR with 0x1b if the
 most important bit of a is set after left-shifting.
 ● Themultiplication's outcome is given back.

 5. mix_column_both(column, bool)
 ● This function applies the MixColumns operation to a single column of the AES
 state matrix.
 ● Depending on whether the matrix is being used for encryption or decryption, it
 multiplies a column as input.
 ● Theinput column has the updated result in place.

 6. mix_columns(matrix, bool)
 ● Theentire state matrix is covered by this function's MixColumns operation.
 ● Eachcolumn of the matrix is iterated over, and each column is modified with the
 mix_column_both() function.
 ● Theinput matrix is updated with the outcome.

 7. left_and_right_shift(arr, bool)
 ● Depending on the boolean value, this function shifts an array's elements left or
 right circularly.
 ● Function performs left shift if bool is True; otherwise, it shifts to the right.
 ● Forthe right shift the last element of the array is moved to the first position and
 similarly right shift

 8. left_shift(arr) and right_shift(arr)
 ● Thesefunctions are utility functions for performing left and right circular shifts.
 ● Withthe appropriate boolean value, they call left_and_right_shift().

 9. shift_row(matrix) and inverse_shift_row(matrix)
 ● TheShiftRows operation for encryption and decryption is carried out by these
 functions.
 ● Thestate matrix's rows are moved in accordance with the requirements of the
 AES algorithm.
 ● Rowsaremoved to the left for encryption and the right for decryption.

10. key_expansion(main_key)
 ● Using the KeyExpansion algorithm in AES, this function generates all round keys
 from the primary encryption key.
 ● Themainkey is first transformed into a 4x4 integer matrix.
 ● Eachword in the expanded key is then iterated over, being derived from the one
 before it.
 ● Forsomeiterations, round constants are used, and each word performs
 operations similar to rotation, substitution, or XOR on the one before it.
 ● Eachinner list represents a 4x4 round key matrix, and the expanded key is
 returned as an array of lists.

 11. add_round_key(text_x, key_x)
 ● Input: text_x- a 4x4 matrix representing the current state of the text, key_x- a
 4x4 matrix representing the current round key.
 ● Output: Returns a new 4x4 matrix obtained by performing an XOR operation
 between each element of text_x and key_x.
 ● Description: The AddRoundKey operation is carried out by this function, which
 XORs each state matrix byte to the round key matrix. During encryption and
 decryption, this operation adds an additional layer of encryption.
 
 12. substitute_bytes(matrix, bool)
 ● Input: matrix- a 4x4 matrix representing the state matrix, bool- a boolean
 indicating whether to use the S-Box for encryption (True) or the inverse S-Box for
 decryption (False).
 ● Output: Modifies the matrix in-place.
 ● Description: During the encryption process, the S-Box lookup table's
 corresponding byte is used in place of each member of the state matrix. The
 inverse S-Box is substituted during decryption. The data becomes more
 confusing as a result of this operation, which also increases the security of the
 encryption process.

 13. AES_encrypt_function(text_hex, all_round_keys)
 ● Input: text_hex- the plaintext represented as a 1D array of hexadecimal strings,
 all_round_keys- a list containing all round keys.
 ● Output: Returns the ciphertext represented as a 1D array of hexadecimal strings.
 ● Description: Using the provided round keys, this function performs AES
 encryption on the input plaintext. As it moves through the encryption
 rounds, it sequentially performs AddRoundKey, SubBytes, ShiftRows, and
 MixColumns. After all rounds have been completed, the final ciphertext is
 obtained.

14. AES_decrypt_function(cipher_text, all_round_keys)
 ● Input: cipher_text- the ciphertext represented as a 1D array of
 hexadecimal strings, all_round_keys- a list containing all round keys.
 ● Output: Returns the plaintext represented as a 1D array of hexadecimal
 strings.
 ● Description: Using the provided round keys, this function decrypts the input
 ciphertext. It performs inverse operations on SubBytes, ShiftRows,
 MixColumn, and AddRoundKey in reverse order as it goes through the
 decryption rounds. After all rounds have been completed, the final plaintext
 is obtained.

 
 References:
 1. GFG
 2. https://medium.com/wearesinch/building-aes-128-from-the-ground-up-with
python-8122af44ebf9
 3. http://blog.simulacrum.me/2019/01/aes-galois
