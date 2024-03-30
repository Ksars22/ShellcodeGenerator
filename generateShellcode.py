import argparse
import subprocess
import time
import pefile

parser = argparse.ArgumentParser(description="Generate Shellcode for x86 and x64 Windows")
parser.add_argument("--arch", type=str, default="x64", help="Architecture: x64 or x86", required=False)
parser.add_argument("--cmd", type=str, help="Command to execute", required=True)

args = parser.parse_args()

def extract_shellcode(file_path):
    pe = pefile.PE(file_path)

    text_section = None
    for section in pe.sections:
        if b'.text' in section.Name.lower():
            text_section = section
            break

    if not text_section:
        print("No .text section found")
        return None
    
    shellcode = text_section.get_data()
    pe.close()
    return shellcode

def search_replace(file_path, search_text, replace_text):
    with open(file_path, "r") as file:
        contents = file.read()

    updated_contents = contents.replace(search_text, replace_text)

    with open(file_path, "w") as file:
        file.write(updated_contents)

def paste_text(file_path, position, text_to_paste):
    with open(file_path, "r") as file:
        contents = file.read()

    updated_contents = contents[:position] + text_to_paste + contents[position:]

    with open(file_path, "w") as file:
        file.write(updated_contents)

def delete_bytes(file_path, start_pos, end_pos):
    with open(file_path, "rb") as file:
        file.seek(0)
        before_bytes = file.read(start_pos)
        file.seek(end_pos)
        after_bytes = file.read()

    with open(file_path, "wb") as file:
        file.write(before_bytes + after_bytes)

def transform_string(input_string):
    char_list = [f"'{char}'" for char in input_string]
    char_list.append('0')
    transformed_string = ','.join(char_list)

    return transformed_string

if (args.arch == "x64"):
    process = subprocess.Popen("copy template.cpp crafted.cpp", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    time.sleep(1)
    formatted_command = transform_string(args.cmd)
    full_line = f"char command[] = {{ {formatted_command} }};\n"
    byte_buffer_start = 262
    cpp_path = "crafted.cpp"
    paste_text(cpp_path, byte_buffer_start, full_line)

    process = subprocess.Popen('bin\\Hostx64\\x64\\cl.exe /c /FA /GS- /I"Includes" crafted.cpp', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    time.sleep(1)
    asm_file = "crafted.asm"
    delete_bytes(asm_file, 105, 123)
    delete_bytes(asm_file, 105, 130)
    delete_bytes(asm_file, 318, 1316)
    stack_alignment = '''
    AlignRSP PROC
        push rsi
        mov rsi, rsp
        and rsp, 0FFFFFFFFFFFFFFF0h
        sub rsp, 020h
        call main
        mov rsp, rsi
        pop rsi
        ret
    AlignRSP ENDP
    '''
    paste_text(asm_file, 357, stack_alignment)
    search_replace(asm_file, "gs:96", "gs:[96]")

    process = subprocess.Popen('bin\\Hostx64\\x64\\ml64.exe crafted.asm /link /entry:AlignRSP', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    time.sleep(1)
    shellcode = extract_shellcode("crafted.exe")
    c_byte_string = ''.join([f"\\x{byte:02x}" for byte in shellcode])
    c_byte_string = f'unsigned char data[] = "{c_byte_string}"'
    print(c_byte_string)
    process = subprocess.Popen('del mllink$.lnk crafted.asm crafted.obj crafted.cpp crafted.exe', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

else:
    process = subprocess.Popen("copy template.cpp crafted.cpp", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    time.sleep(1)
    formatted_command = transform_string(args.cmd)
    full_line = f"char command[] = {{ {formatted_command} }};\n"
    byte_buffer_start = 262
    cpp_path = "crafted.cpp"
    paste_text(cpp_path, byte_buffer_start, full_line)

    process = subprocess.Popen('bin\\Hostx86\\x86\\cl.exe /c /FA /GS- /I"Includes" crafted.cpp', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    time.sleep(1)
    asm_file = "crafted.asm"
    paste_text(asm_file, 176, "assume fs:nothing")
    delete_bytes(asm_file, 200, 220)
    delete_bytes(asm_file, 200, 220)
    process = subprocess.Popen('bin\\Hostx86\\x86\\ml.exe crafted.asm /link /entry:main', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    time.sleep(1)
    shellcode = extract_shellcode("crafted.exe")
    c_byte_string = ''.join([f"\\x{byte:02x}" for byte in shellcode])
    c_byte_string = f'unsigned char data[] = "{c_byte_string}"'
    print(c_byte_string)
    process = subprocess.Popen('del mllink$.lnk crafted.asm crafted.obj crafted.cpp crafted.exe', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)