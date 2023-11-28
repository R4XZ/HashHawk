import os
import pyzipper
from tqdm import tqdm

PASSWORD_COLOR = 'green'


def zip_file():
    # Specify the name of the ZIP file you want to create (with .zip extension)
    zip_file_name = input('Name of the zip file: ')

    # Prompt the user to enter the password for the ZIP file
    password = input('Enter the password for the ZIP file: ')

    # Prompt the user to choose the output directory
    while True:
        output_dir = input('Enter the output directory (or press Enter for the current directory): ')
        if not output_dir:
            output_dir = os.getcwd()  # Use the current directory if no directory is specified
            break
        elif os.path.isdir(output_dir):
            break
        else:
            print('Invalid directory. Please enter a valid directory or press Enter to use the current directory.')

    # Construct the full path to the output ZIP file
    zip_file_path = os.path.join(output_dir, zip_file_name)

    # Create a new ZIP file with the provided password
    with pyzipper.AESZipFile(zip_file_path, 'w', compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES) as zipf:
        zipf.setpassword(password.encode())  # Convert the password to bytes

        # Prompt the user to add files or directories to the ZIP file
        while True:
            file_or_dir = input('Enter the path of a file or directory to add (or press Enter to finish): ')
            if not file_or_dir:
                break  # Stop adding files/directories if Enter is pressed
            elif os.path.exists(file_or_dir):
                if os.path.isfile(file_or_dir):
                    zipf.write(file_or_dir)  # Add the file to the ZIP
                elif os.path.isdir(file_or_dir):
                    zipf.write(file_or_dir, arcname=os.path.basename(file_or_dir))  # Add the directory to the ZIP
                else:
                    print('Invalid path. Please enter a valid file or directory path.')
            else:
                print('Path does not exist. Please enter a valid file or directory path.')

    print(f'Password-protected ZIP file "{zip_file_path}" created successfully.')





def bruteforce_zip():
    # Prompt the user for the ZIP file to crack
    zip_file_path = input('Enter the path to the ZIP file you want to crack: ')

    # Prompt the user for the password list file
    password_list_file = input('Enter the path to the password list file (e.g., rockyou.txt): ')

    # Load passwords from the specified password list file
    with open(password_list_file, 'r', encoding='latin-1') as password_file:
        passwords = [line.strip() for line in password_file]

    # Initialize a flag to track whether the password was found
    password_found = False

    # Create a tqdm progress bar
    progress_bar = tqdm(passwords, desc="Cracking Progress", ascii=True)

    # Attempt to extract the ZIP file with each password
    for password in progress_bar:
        try:
            with pyzipper.AESZipFile(zip_file_path) as zip_file:
                zip_file.pwd = password.encode()
                zip_file.extractall()
                # If extraction succeeds without raising an exception, the password is correct
                password_found = True
                print(f"\nPassword found: {password}")
                break  # Stop if the correct password is found
        except Exception as e:
            pass  # Continue if extraction fails (wrong password)

    # Close the progress bar
    progress_bar.close()

    # If no password is found, display a message
    if not password_found:
        print("Password not found in the list.")





