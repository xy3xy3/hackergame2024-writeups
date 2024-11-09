import os
import subprocess
import sys


def welcome():
    banner = r"""
                                                                                                 ,----,
                                                    ,--.                                       ,/   .`|
  ,----..   ,-.----.       ,---,.    ,---,.       ,--.'|          ,----..     ,---,          ,`   .'  :
 /   /   \  \    /  \    ,'  .' |  ,'  .' |   ,--,:  : |         /   /   \   '  .' \       ;    ;     /
|   :     : ;   :    \ ,---.'   |,---.'   |,`--.'`|  ' :        |   :     : /  ;    '.   .'___,/    ,'
.   |  ;. / |   | .\ : |   |   .'|   |   .'|   :  :  | |        .   |  ;. /:  :       \  |    :     |
.   ; /--`  .   : |: | :   :  |-,:   :  |-,:   |   \ | :        .   ; /--` :  |   /\   \ ;    |.';  ;
;   | ;  __ |   |  \ : :   |  ;/|:   |  ;/||   : '  '; |        ;   | ;    |  :  ' ;.   :`----'  |  |
|   : |.' .'|   : .  / |   :   .'|   :   .''   ' ;.    ;        |   : |    |  |  ;/  \   \   '   :  ;
.   | '_.' :;   | |  \ |   |  |-,|   |  |-,|   | | \   |        .   | '___ '  :  | \  \ ,'   |   |  '
'   ; : \  ||   | ;\  \'   :  ;/|'   :  ;/|'   : |  ; .'        '   ; : .'||  |  '  '--'     '   :  |
'   | '/  .':   ' | \.'|   |    \|   |    \|   | '`--'          '   | '/  :|  :  :           ;   |.'
|   :    /  :   : :-'  |   :   .'|   :   .''   : |              |   :    / |  | ,'           '---'
 \   \ .'   |   |.'    |   | ,'  |   | ,'  ;   |.'               \   \ .'  `--''
  `---`     `---'      `----'    `----'    '---'                  `---`                                 """
    print("\033[1;32;3m")
    print(banner)
    print("\033[0m")


def modify_byte(original_file_path, new_file_path, change_times):
    if not os.path.isfile(original_file_path):
        raise FileNotFoundError("File not found")

    with open(original_file_path, "rb") as f:
        data = bytearray(f.read())

    check_list = []

    for i in range(change_times):
        if i == change_times - 1 and change_times > 0:
            print("[+] I’m seeing things; I didn’t catch that byte clearly.")

        off = int(input("[*] Enter offset: "), 0)
        new_byte = int(input("[*] Enter data: "), 0)

        if not (i == change_times - 1 and change_times > 0):
            if not ((0x70 <= new_byte < 0x80) or new_byte == 0 or new_byte == 0x90):
                raise ValueError("It seems suspicious.")

        if not (0x2790 <= off < 0x82B4):
            raise ValueError(
                "You can only modify the code segment between _start and _term_proc"
            )

        for x in check_list:
            if abs(off - x) <= 8:
                raise ValueError("You cannot change nearby bytes!")

        if i != change_times - 1:
            check_list.append(off)

        data[off] = new_byte

    with open(new_file_path, "wb") as f:
        f.write(data)


def generate_test_file(file_path):
    greeting_data = b"secrets\n"
    with open(file_path, "wb") as f:
        f.write(greeting_data)
    return greeting_data


def test_cat(cat_path, file_path):
    try:
        result = subprocess.run(
            ["su", "nobody", "-s", "/bin/bash", "-c", f"{cat_path} {file_path}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return result.stdout
    except:
        return None


def check_shell_execution():
    hacked_path = "/dev/shm/hacked"
    flag_path = "/flag"

    if not os.path.exists(flag_path):
        print("[-] Failed: ??? where's my flag?")
        return False
    flag = open(flag_path, "r").read()

    if not os.path.exists(hacked_path):
        print("[-] Failed: Haha, green cat is so green.")
        return False

    with open(hacked_path, "r") as f:
        content = f.read().strip()

    if content.startswith("hacked by"):
        player_id = content[len("hacked by ") :].strip()
        if player_id:
            print(
                f"\033[36m\033[1m[+] {player_id}, you are a big hacker! Here's your flag: {flag}\033[0m"
            )
            return True
        else:
            print("[-] Failed: Who are you?")
            return False
    else:
        print("[-] Failed: Who are you?")
        return False


def main():
    welcome()
    subprocess.run(["rm", "-rf", "/dev/shm/play"])
    subprocess.run(["mkdir", "-m", "777", "-p", "/dev/shm/play"])

    ori_cat = "/cat"
    green_cat = "/dev/shm/play/green_cat"
    test_file = "/dev/shm/play/secret"

    n_bytes = int(input("[*] How many bytes do you want to modify? "))
    if not (0 <= n_bytes <= 5):
        raise ValueError("Only 5 bytes can be changed at most!")
    modify_byte(ori_cat, green_cat, n_bytes)
    subprocess.run(["chmod", "+x", green_cat])

    print("[*] Certainly, your green_cat needs to function just like the standard cat.")
    original_data = generate_test_file(test_file)
    cat_output = test_cat(green_cat, test_file)

    if original_data != cat_output:
        print("[-] green_cat failed to run!")
        exit()

    print("RUNNING!")
    subprocess.run(
        [
            "su",
            "nobody",
            "-s",
            "/bin/bash",
            "-c",
            f"{green_cat} {test_file} -",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    check_shell_execution()


if __name__ == "__main__":
    main()
