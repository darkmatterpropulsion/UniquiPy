import hashlib
from pathlib import Path
import os
import shutil
import yaml


BLOCK_SIZE = 65536

''' The following function calculates the sha256 hash of a file specified in "path" argument.
 The hash is calculated in blocks to avoid reading large files that could potentially fill the memory and crash the program.'''
def fingerprint(path):
    hash_method = hashlib.sha256()

    try:
        with open(path, "rb") as input_file:
            buf = input_file.read(BLOCK_SIZE)
            while len(buf) > 0:
                hash_method.update(buf)
                buf = input_file.read(BLOCK_SIZE)
    except Exception as e:
        print(f"[-] An error occurred while opening {path} for hashing: " + e)
        return ''
    return hash_method.hexdigest()


''' The following function starts from "base_path" and searches all the path (recursively)
 of the directories tree. The function return a list containing all the paths that point to files. '''
def search_path(base_path):
    paths = []
    pathlist = Path(base_path).glob("**/*")
    for path in pathlist:
        if os.path.isfile(path):
            paths.append(str(path))
    return paths

'''
 The following function takes the  following arguments:
 - path: The path to the file under analysis
 - hashes: the dictionary containing the hashes
 - key: A string containing the label to access the dictionary
 With this argument in input the function checks if the file's hash has been
 already calculated (if it is, the file is a duplicate) or not. If the hash was not found
 previously, the function add to the hashes dictionary this new value.
 '''
def is_unique(path, hashes, key):
    hash_to_check = fingerprint(path)
    if hash_to_check in hashes[key]:
        return False, hashes[key]
    else:
        hashes[key].append(hash_to_check)
        return True, hashes[key]

'''
 The following function takes the path, that is a string like
 /This/is/the/directory/to/a/file.extension and return the files name and
 the file extension.
'''
def get_file_name_and_extension(path):
    root_name, file_extension = os.path.splitext(path)
    file_name_pieces = root_name.split("/")
    return file_name_pieces[-1], file_extension

'''
The following function generates and store the hashes of the files inside the folder
pointed by "path"
'''
def generate_folder_hash(path):
    hash = []
    paths = search_path(path)
    for single_path in paths:
        hash.append(fingerprint(single_path))
    return hash

'''
The following function create a folder specified in "path".
'''
def create_dir(path):
    if not os.path.exists(path):
        try:
            os.mkdir(path)
            return []
        except FileExistsError:
            print("[!] It appears that the file already exists but was not detected.")
            return generate_folder_hash(path)
        except Exception as e:
            print(f"[-] An error has occurred while checking existence of {path}" + e)
            return []
    else:
        return generate_folder_hash(path)

'''
 The following block read the configuration file
 and create a dictionary with the keys given by the label
 specified in the yaml files. The block also attempt to create
 the directory structor to write the files.
'''
def parse_configuration(data):
    paths_to_check = []
    path_to_write = []
    hashes = {}

    paths_to_check = data["sources"]
    path_to_write = data["destination"]
    for item in data["extensions"]:
        for key in item.keys():
            hash = []
            hash = create_dir("".join(map(str, path_to_write)) + "/" + key)
            hashes[key] = hash
    return hashes, path_to_write, paths_to_check

'''
 This block searches for all the files inside the sources directory and stores
 them in a list
'''
def search_for_files(paths_to_check):
    all_the_files = []
    for path in paths_to_check:
        all_the_files.extend(search_path(path))
    return all_the_files

def copy_files(path,path_to_write,key,file_name,file_extension):
    try:
        shutil.copyfile(
            path,
            "".join(map(str, path_to_write))
            + "/"
            + f"{key}"
            + "/"
            + file_name
            + file_extension,
            )
    except Exception as e:
        print(f"[-] An error has occurred while copying {path} " + e)

    print(
        "[+]"
        + " Writing "
        + "".join(map(str, path_to_write))
        + "/"
        + f"{key}"
        + "/"
        + file_name
        + file_extension
        ).encode(encoding="UTF-8", errors="strict")

'''
 This last block check if each file in all_the_files is unique and if it is so,
 it is written to the directory where it belong.
'''
def write_files(all_the_files, data, hashes, path_to_write):
    for path in all_the_files:
        file_name, file_extension = get_file_name_and_extension(path)
        for item in data["extensions"]:
            for key, values in item.items():
                if file_extension in values:
                    unique, hashes[key] = is_unique(path, hashes, key)
                    if unique:
                            copy_files(path,path_to_write,key,file_name,file_extension)
                    else:
                        print(
                            (
                                "[-]"
                                + " "
                                + "".join(map(str, path_to_write))
                                + "/"
                                + f"{key}"
                                + "/"
                                + file_name
                                + file_extension
                                + " is already presesent"
                            ).encode(encoding="UTF-8", errors="strict")
                        )


def main():

    paths_to_check = []
    path_to_write = []
    all_the_files = []
    hashes = {}

    try:
        with open("uniquiPy.yaml", "r") as f:
            data = yaml.safe_load(f)
            hashes, path_to_write, paths_to_check = parse_configuration(data)
    except FileNotFoundError:
        print("[-] The configuration file uniquiPy.yaml was not found.")
        sys.exit(-1)
    except Exception as e:
        print("An error has occurred while reading the configuration file: " + e)
        
    all_the_files = search_for_files(paths_to_check)

    write_files(all_the_files, data, hashes, path_to_write)


if __name__ == "__main__":
    main()
