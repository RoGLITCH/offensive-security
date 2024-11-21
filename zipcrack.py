import zipfile

file = open('mut_password.list', 'r', errors='ignore')
data = file.read().splitlines()
file.close()

errors = 0
print(len(data))
zipf = zipfile.ZipFile("Notes.zip")

for password in data:
    try:
        zipf.extractall(pwd=password.encode('utf-8'))
        print(f"Found: {password}")
        break
    except (RuntimeError, zipfile.BadZipFile):
        errors += 1

print(errors)
