import os
import sys
import argparse
from ftplib import FTP, error_perm

def download_ftp_dir(ftp, remote_dir, local_dir):
    """
    Recursively download a directory and all its subdirectories from an FTP server.
    Also enumerate permissions, UID/GID, and check writable directories.
    """
    os.makedirs(local_dir, exist_ok=True)
    ftp.cwd(remote_dir)
    file_list = ftp.nlst()

    for item in file_list:
        # Check if item is a directory or file
        if is_directory(ftp, item):
            # Recursively download the directory
            download_ftp_dir(ftp, item, os.path.join(local_dir, item))
            ftp.cwd('..')
        else:
            # Download the file
            local_filepath = os.path.join(local_dir, item)
            with open(local_filepath, 'wb') as f:
                print(f"Downloading {item} to {local_filepath}")
                ftp.retrbinary(f"RETR {item}", f.write)
            
            # Get and store file information
            permissions, uid, gid = get_file_info(ftp, item)
            if 'x' in permissions:
                write_to_file('ftp/Executable_Files.txt', f"{remote_dir}/{item}")
            write_to_file('ftp/UID_GID.txt', f"{remote_dir}/{item}: UID={uid}, GID={gid}")

def is_directory(ftp, name):
    """
    Check if a given path on the FTP server is a directory.
    """
    original_cwd = ftp.pwd()
    try:
        ftp.cwd(name)
        ftp.cwd(original_cwd)
        return True
    except error_perm:
        return False

def get_file_info(ftp, filename):
    """
    Retrieve file permissions, UID, and GID from an FTP 'LIST' command.
    """
    file_info = []
    ftp.retrlines(f'LIST {filename}', file_info.append)
    # Example format: '-rw-r--r-- 1 user group 123 Jan 01 12:34 filename'
    parts = file_info[0].split()
    permissions = parts[0]
    uid = parts[2]
    gid = parts[3]
    return permissions, uid, gid

def can_upload(ftp):
    """
    Check if the current user can upload files by trying to create a temp file.
    """
    try:
        ftp.storbinary('STOR temp_upload_test.txt', open('/dev/null', 'rb'))
        ftp.delete('temp_upload_test.txt')  # Clean up the test file
        return True
    except error_perm:
        return False

def write_to_file(filename, content):
    """
    Write a line of text to a specified file.
    """
    with open(filename, 'a') as f:
        f.write(content + '\n')


parser = argparse.ArgumentParser()
parser.add_argument("-target")
parser.add_argument("-port", default=21)
parser.add_argument("-user", default="anonymous")
parser.add_argument("-passwd", default="")
parser.add_argument("-output-path", default='ftp/content')
args = parser.parse_args()

# Initialize and create necessary output files
os.makedirs('ftp', exist_ok=True)
open('ftp/UID_GID.txt', 'w').close()
open('ftp/Can_Upload.txt', 'w').close()
open('ftp/Executable_Files.txt', 'w').close()
open('ftp/Writable_Folders.txt', 'w').close()

# Connect to FTP server
ftp = FTP()
ftp.connect(args.target, args.port)

try:
    ftp.login(args.user, args.passwd)
    print(f"Logged-in successfully with user {args.user} and password {args.passwd}")
except Exception as e:
    print(f"Failed to log-in, check credentials")
    sys.exit(0)

# Check upload capability
if can_upload(ftp):
    write_to_file('ftp/Can_Upload.txt', 'YES - Can upload files')
else:
    write_to_file('ftp/Can_Upload.txt', 'NO - Cannot upload files')

# Start downloading from the root directory
download_ftp_dir(ftp, '/', args.output_path)

# Close the FTP connection
ftp.quit()

