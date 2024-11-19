import sys

def encrypt_file_inplace(input_file_path, output_file_path, password):
    """
    Encrypts the content of the file using an 8-byte password
    and overwrites the file with the encrypted content.

    :param input_file_path: Path to the file to be encrypted
    :param output_file_path: Output file path
    :param password: 8-byte password for encryption
    """
    if len(password) > 8:
        raise ValueError("Password must be 8 bytes or less.")
    
    # Pad the password to 8 bytes if it's shorter
    password_bytes = password.encode('utf-8').ljust(8, b'\0')

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


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python script_name.py <input_file_path> <output_file_path> <password>")
        sys.exit(1)

    input_file_path = sys.argv[1]
    output_file_path = sys.argv[2]
    password = sys.argv[3]

    try:
        encrypt_file_inplace(input_file_path, output_file_path, password)
    except ValueError as e:
        print(e)
        sys.exit(1)
