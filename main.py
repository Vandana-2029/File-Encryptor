def encrypt_file_inplace(input_file_path, output_file_path, password):
    """
    Encrypts the content of the file using an 8-byte password
    and overwrites the file with the encrypted content.

    :param input_file_path: Path to the file to be encrypted
    :param output_file_path: Output file path
    :param password: 8-byte password for encryption
    """
    if len(password) != 8:
        raise ValueError("Password must be exactly 8 bytes.")
    
    password_bytes = password.encode('utf-8')  # Convert password to bytes

    try:
        # Read the original file content
        with open(input_file_path, 'rb') as file:
            data = file.read()

        # Encrypt the content in memory
        encrypted_data = bytearray()
        for i in range(0, len(data), 8):
            chunk = data[i:i+8]  # Take 8-byte chunk
            encrypted_block = bytes([b ^ p for b, p in zip(chunk, password_bytes)])
            encrypted_data.extend(encrypted_block)

        # Overwrite the file with the encrypted content
        with open(output_file_path, 'wb') as file:
            file.write(encrypted_data)

        print(f"File encrypted successfully and saved as {output_file_path}")
    except FileNotFoundError:
        print(f"Error: File '{input_file_path}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")


# Example usage
if __name__ == "__main__":
    input_file_path = "Testing\\img3.png"
    output_file_path = "Testing\\img4.png"
    password = "password"           # Replace with your 8-byte password

    encrypt_file_inplace(input_file_path, output_file_path, password)
