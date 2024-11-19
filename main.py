def encrypt_file(input_file, password, output_file):
    """
    Encrypts the content of the input file using an 8-byte password
    and saves it to the output file.

    :param input_file: Path to the input file to be encrypted
    :param password: 8-byte password for encryption
    :param output_file: Path to save the encrypted file
    """
    if len(password) != 8:
        raise ValueError("Password must be exactly 8 bytes.")
    
    password_bytes = password.encode('utf-8')  # Convert password to bytes

    try:
        with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
            while chunk := infile.read(8):  # Read file in 8-byte blocks
                # XOR the block with the password
                encrypted_block = bytes([b ^ p for b, p in zip(chunk, password_bytes)])
                outfile.write(encrypted_block)  # Write the encrypted block to the output file

        print(f"File encrypted successfully and saved as {output_file}")
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")


# Example usage
if __name__ == "__main__":
    input_file = "Testing\\img2.png"       # Replace with the path to your input file
    password = "password"           # Replace with your 8-byte password
    output_file = "Testing\\img2.png"   # Replace with the desired output file path

    encrypt_file(input_file, password, output_file)
