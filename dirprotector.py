
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
hint_fname = "hint.txt"

commands = {
    'lock': "Encrypts all files in the directory (not subdirectories)",
    'unlock': "Decrypts the files encrypted"
}

enc_info_headers = ["file_extension", "salt", "token"]

# -------- Main Activity -------
def main():
    print(" + DIR PROTECTOR (ctrl-c to exit):")
    args = sys.argv; args.pop(0)
    current_fname = os.path.basename(__file__)
    target_dir = get_target_dir(args)
    print(f'[%] Target dir -> "{target_dir}"')
    if len(args) > 0:        
        if "lock" in args: lock(dir_path=target_dir)
        elif "unlock" in args: unlock(dir_path=target_dir)
        else: activate_shell(dir_path=target_dir)
    else: activate_shell(dir_path=target_dir)
        
def activate_shell(dir_path:Path):
    print_help()
    print(" -  Enter command: ")
    valid_command = False
    while not valid_command:
        command = str(input("> "))
        if command in commands:
            valid_command = True
            if command == 'lock': lock(dir_path)
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
    dirs = [name for name in os.listdir(dir_path) if os.path.isdir(name)]
    for d in dirs:
        if locked_dirname+"-" in d:
            return dir_path/d
    
def is_locked(dir_path:Path):
    dirs = [name for name in os.listdir(dir_path) if os.path.isdir(name)]
    for d in dirs:
        if locked_dirname+"-" in d:
            return True
    return False
        
def print_help():
    print("[?] Commands:")
    for command, info in commands.items():
        print(f"     - {command}: {info}")
        
def clean_trash(locked_dir_path:Path):
    def del_rw(action, name, exc):
        os.chmod(name, stat.S_IWRITE)
        os.remove(name)
    shutil.rmtree(locked_dir_path, onerror=del_rw)
    
                
# ---------- COMMANDS --------- 
def lock(dir_path:Path):
    # Vemos si este directorio ya ha sido encriptado
    if is_locked(dir_path):
        print(f"[!] This directory is already locked")
        return
    password = str(input(" + Choose a password: "))
    print(f" -> Password chosen: '{password}'")
    print("[%] Locking directory...")
    print(f"[-] Creating '{locked_dirname}' directory")
    dest_dir = Path(dir_path/(locked_dirname+f"-{get_date(path_friendly=True)}"))
    if not os.path.exists(dest_dir): os.mkdir(dest_dir)
    
    
    file_names = [name for name in os.listdir(dir_path) if os.path.isfile(name)]
    salt_dict = {}
    for fname in file_names:
        
        src_path = dir_path/fname
        # Movemos el fichero a la carpeta .locked
        dest_path = dest_dir/fname
        try:
            shutil.move(src_path, dest_path)
        except Exception as err:
            print(f"[!] Error moving '{fname}' into '{locked_dirname}' directory -> '{err}'")
            continue
        print(f"[-] Encrypting '{fname}'...")
        # Encriptamos el fichero
        try:
            salt = generate_salt()
            key = derive(password.encode(), salt)
            encrypt_file(dest_path, key)
        except Exception as err:
            print(f"[!] Error encrypting '{fname}' -> '{err}'")
        else:
            salt_dict[fname] = salt
    
    info_dir_path = dest_dir/info_dirname
    os.mkdir(info_dir_path)
    # Guardamos el hash salteado de la password
    pw_salt = generate_salt()
    hashed_pw = derive(password.encode(), pw_salt)
    pw_file_path = info_dir_path/password_fname
    with open(pw_file_path, 'wb') as salt_file:
        pickle.dump({hashed_pw: pw_salt}, salt_file)

    # Guardamos las salts utilizadas en un fichero a parte 
    salt_file_path = info_dir_path/salt_cellar_fname
    with open(salt_file_path, 'wb') as salt_file:
        pickle.dump(salt_dict, salt_file)
        
    # Creamos un fichero para que el usuario pude guardar un pista de la contraseña
    hint_file_path = dir_path/hint_fname
    with open(hint_file_path, 'w') as hint_file:
        msg = "# Add a hint for your locked dir password:\n      => hint: ''"
        hint_file.write(msg)

    print(f"[%] Finished -> '{dir_path}' has been locked")
    
def unlock(dir_path:Path):
    # Vemos si el directorio a sido encriptado antes
    if not is_locked(dir_path):
        print(f"[!] This directory hasn't been locked yet")
        return
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
    
    file_names = []
    for fname in os.listdir(locked_dir_path):
        cond2 = fname != password_fname and fname != salt_cellar_fname
        if os.path.isfile(locked_dir_path/fname) and cond2:
            file_names.append(fname)
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
            continue
        print(f"[-] Decrypting '{fname}'...")
        # desencriptamos el fichero
        try:
            salt = salt_dict[fname]
            key = derive(password.encode(), salt)
            decrypt_file(dest_path, key)
        except Exception as err:
            print(f"[!] Error decrypting '{fname}' -> '{err}'")
        else:
            salt_dict.pop(fname)
    
    if len(salt_dict) == 0:
        clean_trash(locked_dir_path)
    
    print(f"[%] Finished -> '{dir_path}' has been unlocked")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("[!] Exit")
        exit(1)
    except Exception as err:
        print(f"[!] Unexpected Error: {err}")
        input("-> Press Enter to exit")
        exit(1)
    
