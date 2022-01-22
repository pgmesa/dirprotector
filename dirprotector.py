
# Built-in modules
import os
import sys
import stat
import shutil
import pickle
import platform
import datetime as dt
from pathlib import Path

# Dependencies
from crypt_utilities.hashes import derive, generate_salt
from crypt_utilities.symmetric import decrypt_file, encrypt_file

dir_ = Path(os.getcwd()).resolve()
system = platform.system()
locked_dirname = '.locked'
info_dirname = '.__info__'
password_fname = '.__password__'
salt_cellar_fname = '.__salt-cellar__'
hint_fname = "__hint__.txt"

commands = {
    'lock': "Encrypts all files in the directory (not subdirectories). -r for subdirectories, -p=<password>,-h=<hint>,-d=<iterations>",
    'unlock': "Decrypts the files encrypted. -p=<password>, -n to avoid relock prompt",
}

enc_info_headers = ["file_extension", "salt", "token"]
ignored_files = ['desktop.ini', '.DS_Store']

win_venvs = ["Scripts/activate.bat", "Scripts/Activate.ps1"]
posix_venvs = ["bin/activate","bin/activate.fish","bin/activate.csh","bin/Activate.ps1"]

default_derive_iters = 100000 

# -------- Main Activity -------
def main():
    print(" + DIR PROTECTOR (ctrl-c to exit):")
    args = sys.argv; args.pop(0)
    print(args,"(args)")
    current_fname = os.path.basename(__file__)
    target_dir = get_target_dir(args)
    if len(args) > 0:
        try: password = [a for a in args if "-p=" in a][0].split("=")[1]
        except IndexError: password = None
        command = args[0]
        if "lock" == command or "autolock" == command: 
            recursively = False; 
            if "-r" in args: 
                recursively = True 
            try: hint = [a for a in args if "-h=" in a][0].split("=")[1]
            except IndexError: hint = None
            try: derive_iters = int([a for a in args if "-d=" in a][0].split("=")[1])
            except IndexError: derive_iters = default_derive_iters
            params = dict(
                dir_path=target_dir, r=recursively, password=password, hint=hint, iters=derive_iters
            )
            lock(**params)
        elif "unlock" == command:
            relock = None; 
            if "-n" in args: 
                relock = False
            unlock(dir_path=target_dir, password=password, relock=relock)
        else:
            print(f"[!] '{command}' is not a valid command!") 
            print_help()
    else: print_help()
                
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

def is_venv(dir_path:Path) -> bool:
    venv_paths = win_venvs
    if system != "Windows":
        venv_paths = posix_venvs
    for path in venv_paths:
        act_path = dir_path/path
        if os.path.exists(act_path): 
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
def lock(dir_path:Path, r=False, password:str=None, hint:str=None, iters=default_derive_iters):
    print(f'[%] Target dir -> "{dir_path}"')
    # Vemos si este directorio ya ha sido encriptado
    if is_locked(dir_path):
        print(f"[!] This directory is already locked")
        return
    # Vemos si el directorio es un entorno virtual para ignorarlo
    if is_venv(dir_path):
        print(f"[!] This directory is a virtual environment and is not worth to encrypt")
        return
    dir_files = [name for name in os.listdir(dir_path) if os.path.isfile(dir_path/name) and name not in ignored_files]
    if not r:
        if len(dir_files) == 0:
            print(f"[!] This directory has no files to encrypt 'lock -r for subdirectories'")
            return
    elif len(os.listdir(dir_path)) == 0:
        print(f"[!] This directory is empty")
        return
    if r: print("[%] Locking directory recursively...")
    else: print("[%] Locking directory...")
    print(f" -> Derive Iterations = {iters}")
    if password is None:
        password = str(input(" + Choose a password: "))
    print(f" -> Password chosen: '{password}'")
    if hint is None:
        hint = str(input(" + Add a hint (press enter to skip): "))
    if hint != "":
        print(f" -> Hint added: '{hint}'")
    print(f"[-] Creating '{locked_dirname}' directory")
    dest_dir = Path(dir_path/(locked_dirname+f"-{get_date(path_friendly=True)}"))
    outcome = _lock(dir_path, dest_dir, password, iters, r=r)
    
    info_dir_path = dest_dir/info_dirname
    if not os.path.exists(info_dir_path): os.mkdir(info_dir_path)
    # Guardamos el hash salteado de la password
    pw_salt = generate_salt()
    hashed_pw = derive(password.encode(), pw_salt, iterations=iters)
    pw_file_path = info_dir_path/password_fname
    with open(pw_file_path, 'wb') as salt_file:
        pickle.dump({hashed_pw: pw_salt, "iters": iters}, salt_file)
    # Creamos un fichero para que el usuario pude guardar un pista de la contraseña
    hint_file_path = dir_path/hint_fname
    with open(hint_file_path, 'w') as hint_file:
        msg = f"[%] Add a hint for your locked directory password:\n    => hint: '{hint}'"
        hint_file.write(msg)

    if outcome == 0:
        print(f"[%] Finished -> '{dir_path}' has been locked")
    else:
        print(f"[!] Some errors came up while locking '{dir_path}'")

def _lock(dir_path:Path, dest_dir:Path, password, iters:int, r=False):
    # Vemos si el directorio es un entorno virtual para ignorarlo
    if is_venv(dir_path):
        print(f"[%] Ignoring '/{dir_path.name}' (virtualenv)")
        return -1
    if not os.path.exists(dest_dir): os.mkdir(dest_dir)
    dir_outcome = 0
    if r:
        subdirectories = [name for name in os.listdir(dir_path) if os.path.isdir(dir_path/name) and not locked_dirname+"-" in name]
        for subdir in subdirectories:
            outcome = _lock(dir_path/subdir, dest_dir/subdir, password, iters, r=r) 
            if outcome == 0:
                rmtree(dir_path/subdir)
            elif outcome == 1:
                dir_outcome = 1
    file_names = [name for name in os.listdir(dir_path) if os.path.isfile(dir_path/name) and name not in ignored_files]
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
            key = derive(password.encode(), salt, iterations=iters)
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
    
def unlock(dir_path:Path, password:str=None, relock:bool=None):
    print(f'[%] Target dir -> "{dir_path}"')
    # Vemos si el directorio a sido encriptado antes
    if not is_locked(dir_path):
        print(f"[!] This directory hasn't been locked yet")
        return
    r = is_recursively_locked(dir_path)
    print(" -> recursively locked =", r)
    hint = get_hint(dir_path)
    print(f" -> hint = '{hint}'")
    locked_dir_path = get_locked_dirpath(dir_path) 
    if password is None:
        password = str(input(" + Introduce the password: "))
    print(f" -> Password used: '{password}'")
    # Recuperamos la contrase�a
    with open(locked_dir_path/info_dirname/password_fname, 'rb') as file:
        pw_info = pickle.load(file)
        og_hashed_pw =list(pw_info.keys())[0]
        pw_salt = pw_info[og_hashed_pw]
        iters = pw_info["iters"] # try: 
        # except: iters = 400000
    # Vemos si la contrase�a es correcta
    hasehd_pw = derive(password.encode(), pw_salt, iterations=iters)
    if hasehd_pw != og_hashed_pw:
        print("[!] Incorrect password")
        return
    print("[%] Unlocking directory...")
    outcome = _unlock(locked_dir_path, dir_path, password, iters)
    
    if outcome == 0:
        clean_trash(locked_dir_path)
        print(f"[%] Finished -> '{dir_path}' has been unlocked")
        if relock is None:
            answer = str(input(" + Lock again with same credentials? (y/n): "))
        if relock or ("answer" in locals() and answer.lower() == "y"):
            lock(dir_path, r=r, password=password, hint=hint)      
        else:
            print(f"[%] Not locking again")
    else:
        print(f"[!] Some errors came up while unlocking '{dir_path}'")
    
def _unlock(locked_dir_path:Path, dir_path:Path, password, iters:int) -> int:
    subdirectories = [name for name in os.listdir(locked_dir_path) if os.path.isdir(locked_dir_path/name) and name != info_dirname]
    dir_outcome = 0
    for subdir in subdirectories:
        if not os.path.exists(dir_path/subdir): os.mkdir(dir_path/subdir)
        outcome = _unlock(locked_dir_path/subdir, dir_path/subdir, password, iters)
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
            key = derive(password.encode(), salt, iterations=iters)
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
    
