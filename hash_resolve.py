import pefile # pip install pefile
import os
import sys
import psutil # pip install psutil

hashes = list(set([0x726774C, 0x6B8029, 0xE0DF0FEA, 0x6174A599, 0x5FC8D902, 0xE553A458, 0x56A2B5F0, 0x300f2f0B, 0x614D6E75]))

def ascii2unicode(string):
    u_string = ''
    for i in range(0,len(string)):   
        u_string += string[i]
        u_string += "\x00"
    u_string += "\x00\x00"
    return u_string

def ror(dword, step):
    dword = dword & 0xffffffff
    step = step % 32
    return int("{:032b}".format(dword)[-step:] +  "{:032b}".format(dword)[:-step],2)

def hash(string):
    string2 = bytearray(string)
    h = 0
    for b in string2:
        h = ror(h, 0xD)
        h = (h + b) & 0xffffffff
    return h

def hash_dll(string):
    return hash(ascii2unicode(string.upper()).encode('utf-8'))

def hash_function(string, hsh_dll):
    return (hash(string+b"\x00") + hsh_dll) & 0xffffffff

p = psutil.Process( os.getpid() )

for dll in p.memory_maps():
    try:
        pe = pefile.PE(dll.path)
        pe.DIRECTORY_ENTRY_EXPORT.symbols
    except:
        continue
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if str(exp.name) == 'None': continue
        file = os.path.basename(dll.path)
        hsh_dll = hash_dll(file)
        hsh_fn = hash_function(exp.name, hsh_dll)
        if hsh_fn in hashes:
            print(file, hex(hsh_dll), exp.name, hex(hsh_fn))
            hashes.remove(hsh_fn)
            if len(hashes) == 0: sys.exit()
