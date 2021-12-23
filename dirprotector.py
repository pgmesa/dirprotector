
import os
import sys
import stat
import shutil
import pickle
import datetime as dt
from pathlib import Path
from encryption.hashes import derive, generate_salt
from encryption.symmetric import decrypt_file, encrypt_file

dir_ = Path(os.getcwd()).resolve()
locked_dirname = '.locked'
info_dirname = '.__info__'
password_fname = '.__password__'
salt_cellar_fname = '.__salt-cellar__'
hint_fname = "__hint__.txt"

commands = {
    'lock': "Encrypts all files in the directory (not subdirectories). Add -r for subdirectories",
    'unlock': "Decrypts the files encrypted. Add -r for subdirectories"
}

enc_info_headers = ["file_extension", "salt", "token"]

# -------- Main Activity -------
def main():
    print(" + DIR PROTECTOR (ctrl-c to exit):")
    args = sys.argv; args.pop(0)
    print(args,"(args)")
    current_fname = os.path.basename(__file__)
    target_dir = get_target_dir(args)
    print(f'[%] Target dir -> "{target_dir}"')
    if len(args) > 0:
        recursively = False
        if "-r" in args: 
            recursively = True 
        if "lock" in args: lock(dir_path=target_dir, r=recursively)
        elif "unlock" in args: unlock(dir_path=target_dir)
        else: activate_shell(dir_path=target_dir)
    else: activate_shell(dir_path=target_dir)
        
def activate_shell(dir_path:Path):
    print_help()
    print(" -  Enter command: ")
    valid_command = False
    while not valid_command:
        command_line = str(input("> ")).split(" ")
        command = command_line[0]
        if command in commands:
            recursively = False
            if len(command_line) > 1 and command_line[1] == "-r": 
                recursively = True
            valid_command = True
            if command == 'lock': lock(dir_path, recursively)
            elif command == 'unlock': unlock(dir_path)
        else:
            print(f"[!] '{command}' command doesn't exist in the program")
                
# ---------- UTILS ----------           
def get_target_dir(sys_args:list) -> Path:
    target_dir = dir_
    for arg in sys_args:
        if "dirpath=" in arg:
            target_dir = Path(str(arg.removeprefix("dirpath="))).resolve()
            break
        
    return target_dir
    
def get_date(path_friendly:bool=False) -> str:
    datetime = dt.datetime.now()
    if path_friendly:
        date = str(datetime.date())
        time = str(datetime.time()).replace(':', "-").replace('.', '_')
        return date+"_"+time
    else:
        return str(datetime)

def get_locked_dirpath(dir_path:Path):
    dirs = [name for name in os.listdir(dir_path) if os.path.isdir(dir_path/name)]
    for d in dirs:
        if locked_dirname+"-" in d:
            return dir_path/d
        
def get_hint(dir_path:Path) -> str:
    if os.path.exists(dir_path/hint_fname):
        return (dir_path/hint_fname).read_text().split("'")[1]
    return ''
        
def is_locked(dir_path:Path):
    dirs = [name for name in os.listdir(dir_path) if os.path.isdir(dir_path/name)]
    for d in dirs:
        if locked_dirname+"-" in d:
            return True
    return False

def is_recursively_locked(dir_path:Path):
    if is_locked(dir_path):
        locked_path = get_locked_dirpath(dir_path)
        dirs = [name for name in os.listdir(locked_path) if os.path.isdir(locked_path/name)]
        if len(dirs) > 1:
            # Hay mas de un directorio en a parte del de .__info__ => lock -r
            return True 
    return False
      
def print_help():
    print("[?] Commands:")
    for command, info in commands.items():
        print(f"     - {command}: {info}")
        
def clean_trash(locked_dir_path:Path):
    rmtree(locked_dir_path)
    os.remove(locked_dir_path.parent/hint_fname)

def rmtree(parent_dir:Path):
    def del_rw(action, name, exc):
        os.chmod(name, stat.S_IWRITE)
        os.remove(name)
    shutil.rmtree(parent_dir, onerror=del_rw)
                
# ---------- COMMANDS --------- 
def lock(dir_path:Path, r=False, password:str=None, hint:str=None):
    # Vemos si este directorio ya ha sido encriptado
    if is_locked(dir_path):
        print(f"[!] This directory is already locked")
        return
    if len(os.listdir(dir_path)) == 0:
        print(f"[!] This directory is empty")
        return
    if r: print("[%] Locking directory recursively...")
    else: print("[%] Locking directory...")
    if password is None:
        password = str(input(" + Choose a password: "))
    print(f" -> Password chosen: '{password}'")
    if hint is None:
        hint = str(input(" + Add a hint (press enter to skip): "))
    if hint != "":
        print(f" -> Hint added: '{hint}'")
    print(f"[-] Creating '{locked_dirname}' directory")
    dest_dir = Path(dir_path/(locked_dirname+f"-{get_date(path_friendly=True)}"))
    outcome = _lock(dir_path, dest_dir, password, r=r)
    
    info_dir_path = dest_dir/info_dirname
    if not os.path.exists(info_dir_path): os.mkdir(info_dir_path)
    # Guardamos el hash salteado de la password
    pw_salt = generate_salt()
    hashed_pw = derive(password.encode(), pw_salt)
    pw_file_path = info_dir_path/password_fname
    with open(pw_file_path, 'wb') as salt_file:
        pickle.dump({hashed_pw: pw_salt}, salt_file)
    # Creamos un fichero para que el usuario pude guardar un pista de la contraseña
    hint_file_path = dir_path/hint_fname
    with open(hint_file_path, 'w') as hint_file:
        msg = f"[%] Add a hint for your locked directory password:\n    => hint: '{hint}'"
        hint_file.write(msg)

    if outcome == 0:
        print(f"[%] Finished -> '{dir_path}' has been locked")
    else:
        print(f"[!] Some errors came up while locking '{dir_path}'")

def _lock(dir_path:Path, dest_dir:Path, password, r=False):
    if not os.path.exists(dest_dir): os.mkdir(dest_dir)
    dir_outcome = 0
    if r:
        subdirectories = [name for name in os.listdir(dir_path) if os.path.isdir(dir_path/name) and not locked_dirname+"-" in name]
        for subdir in subdirectories:
            outcome = _lock(dir_path/subdir, dest_dir/subdir, password, r=r) 
            if outcome == 0:
                rmtree(dir_path/subdir)
            else:
                dir_outcome = 1
    file_names = [name for name in os.listdir(dir_path) if os.path.isfile(dir_path/name)]
    if len(file_names) == 0: return dir_outcome
    salt_dict = {}
    for fname in file_names:
        src_path = dir_path/fname
        # Movemos el fichero a la carpeta destino
        dest_path = dest_dir/fname
        try:
            shutil.move(src_path, dest_path)
        except Exception as err:
            print(f"[!] Error moving '{fname}' into '{locked_dirname}' directory -> '{err}'")
            dir_outcome = 1
            continue
        print(f"[-] Encrypting '{fname}'...")
        # Encriptamos el fichero
        try:
            salt = generate_salt()
            key = derive(password.encode(), salt)
            encrypt_file(dest_path, key)
        except Exception as err:
            print(f"[!] Error encrypting '{fname}' -> '{err}'")
            dir_outcome = 1
        else:
            salt_dict[fname] = salt
    
    info_dir_path = dest_dir/info_dirname
    if not os.path.exists(info_dir_path): os.mkdir(info_dir_path)

    # Guardamos las salts utilizadas en un fichero a parte 
    salt_file_path = info_dir_path/salt_cellar_fname
    with open(salt_file_path, 'wb') as salt_file:
        pickle.dump(salt_dict, salt_file)
        
    return dir_outcome
 
    
def unlock(dir_path:Path):
    # Vemos si el directorio a sido encriptado antes
    if not is_locked(dir_path):
        print(f"[!] This directory hasn't been locked yet")
        return
    r = is_recursively_locked(dir_path)
    print(" -> recursively locked =", r)
    hint = get_hint(dir_path)
    print(f" -> hint = '{hint}'")
    locked_dir_path = get_locked_dirpath(dir_path) 
    password = str(input(" + Introduce the password: "))
    print(f" -> Password used: '{password}'")
    # Recuperamos la contrase�a
    with open(locked_dir_path/info_dirname/password_fname, 'rb') as file:
        pw_info = pickle.load(file)
        og_hashed_pw =list(pw_info.keys())[0]
        pw_salt = pw_info[og_hashed_pw]
    # Vemos si la contrase�a es correcta
    hasehd_pw = derive(password.encode(), pw_salt)
    if hasehd_pw != og_hashed_pw:
        print("[!] Incorrect password")
        return
    print("[%] Unlocking directory...")
    outcome = _unlock(locked_dir_path, dir_path, password)
    
    if outcome == 0:
        clean_trash(locked_dir_path)
        print(f"[%] Finished -> '{dir_path}' has been unlocked")
        answer = str(input(" + Lock again with same credentials? (y/n): "))
        if answer.lower() == "y":
            lock(dir_path, r=r, password=password, hint=hint)      
        else:
            print(f"[%] Not locking again")  
    else:
        print(f"[!] Some errors came up while unlocking '{dir_path}'")
    
def _unlock(locked_dir_path:Path, dir_path:Path, password) -> int:
    subdirectories = [name for name in os.listdir(locked_dir_path) if os.path.isdir(locked_dir_path/name) and name != info_dirname]
    dir_outcome = 0
    for subdir in subdirectories:
        if not os.path.exists(dir_path/subdir): os.mkdir(dir_path/subdir)
        outcome = _unlock(locked_dir_path/subdir, dir_path/subdir, password)
        if outcome == 0:
            rmtree(locked_dir_path/subdir)
        else:
            dir_outcome = 1
    file_names = [name for name in os.listdir(locked_dir_path) if os.path.isfile(locked_dir_path/name)]
    if len(file_names) == 0: return dir_outcome
    with open(locked_dir_path/info_dirname/salt_cellar_fname, 'rb') as salt_file:
        salt_dict = pickle.load(salt_file)
    for fname in file_names:
        src_path = locked_dir_path/fname
        # Movemos el fichero al directorio original
        dest_path = dir_path/fname
        try:
            shutil.move(src_path, dest_path)
        except Exception as err:
            print(f"[!] Error moving '{fname}' into original directory -> '{err}'")
            dir_outcome = 1
            continue
        print(f"[-] Decrypting '{fname}'...")
        # desencriptamos el fichero
        try:
            salt = salt_dict[fname]
            key = derive(password.encode(), salt)
            decrypt_file(dest_path, key)
        except Exception as err:
            print(f"[!] Error decrypting '{fname}' -> '{err}'")
            dir_outcome = 1
        else:
            salt_dict.pop(fname)
    
    file_names = [name for name in os.listdir(locked_dir_path) if os.path.isfile(locked_dir_path/name)]
    if len(file_names) > 0 or dir_outcome == 1: return 1
    return 0

if __name__ == "__main__":
    try:
        print("[%] Program started")
        main()
        print("[%] Program finished successfully")
    except KeyboardInterrupt:
        print("[!] Exit")
        exit(1)
    except Exception as err:
        print(f"[!] Unexpected Error: {err}")
        input("-> Press Enter to exit")
        exit(1)
    
