#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pow import *
r = remote('up23.zoolab.org', 10363)
solve_pow(r)
l = r.recvuntil(' challenges').decode()
count = int(l.rsplit(' ', 2)[-2])
print(count)
l = r.recvline_endswith('base64')


print(r.recvline()) # skip empty line

for i in range(count):
    l = r.recvuntil('?').decode()
    # print(f'recv {l}')
    # print(l.rsplit(' ', 5))
    _, number1, op, number2, _, _ = l.rsplit(' ', 5)
    
    print(number1, op, number2)
    number1 = int(number1)
    number2 = int(number2)

    match op:
        case '+':
            ans = number1 + number2
        case '-':
            ans = number1 - number2
        case '*':
            ans = number1 * number2
        case '/':
            ans = number1 / number2
        case '//':
            ans = number1 // number2
        case '**':
            ans = number1 ** number2
        case '%':
            ans = number1 % number2
        case _:
            print(f'unknown op {op}')

    number_bytes = ans.to_bytes((ans.bit_length() + 7) // 8, byteorder="little")
    encoded = base64.b64encode(number_bytes)
    print(f'send ans {ans} in base64 {encoded}')
    r.sendline(encoded)

    


r.interactive()
r.close()