from flask import Flask, render_template, request, send_file
import os

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
OUTPUT_FOLDER = "output"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)


def encrypt_file_inplace(input_file_path, output_file_path, password):
    """
    Encrypts the content of the file using an 8-byte password
    and overwrites the file with the encrypted content.

    :param input_file_path: Path to the file to be encrypted
    :param output_file_path: Output file path
    :param password: Password for encryption (up to 8 bytes)
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

        # Write the encrypted content to the output file
        with open(output_file_path, 'wb') as file:
            file.write(encrypted_data)

    except FileNotFoundError:
        raise FileNotFoundError(f"File '{input_file_path}' not found.")
    except Exception as e:
        raise e


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        # Handle file upload and password input
        uploaded_file = request.files.get("file")
        password = request.form.get("password")

        if not uploaded_file:
            return "Please upload a file.", 400

        if not password:
            return "Please enter a password.", 400

        if len(password) > 8:
            return "Password must be 8 bytes or less.", 400

        # Save uploaded file
        input_file_path = os.path.join(UPLOAD_FOLDER, uploaded_file.filename)
        uploaded_file.save(input_file_path)

        # Encrypt file
        output_file_name = f"encrypted_{uploaded_file.filename}"
        output_file_path = os.path.join(OUTPUT_FOLDER, output_file_name)

        try:
            encrypt_file_inplace(input_file_path, output_file_path, password)
        except Exception as e:
            return str(e), 500

        # Send file directly for download with the option to save it
        return send_file(output_file_path, as_attachment=True, download_name=output_file_name)

    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)
