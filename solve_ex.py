# encoding: utf-8

from pwn import *
from Crypto.Util.number import *
from Crypto.Random.random import *
import sys

def str2int(s):
    return int(s.encode("hex"), 16)

def int2hexstr(n):
    s = "{:0x}".format(n)
    if len(s) % 2 == 1:
        s = "0" + s
    return s

def int2str(n):
    return int2hexstr(n).decode("hex")

def encrypt(n, g, m):
    assert(m < n)
    n2 = n * n

    r = randint(0, n)
    return (pow(g, m % n2, n2) * pow(r, n, n2)) % n2

def main():
    conn = remote("localhost", 8888)
    print(conn.recvline())
    n = int(conn.recvline().split(":")[1])
    g = int(conn.recvline().split(":")[1])
    l = int(conn.recvline().split(":")[1])
    mu = int(conn.recvline().split(":")[1])
    print("n:{}".format(n))
    print("g:{}".format(g))
    print("l:{}".format(l))
    print("µ:{}".format(mu))
    print(conn.recvuntil(">>"))

    if len(sys.argv) == 1:
        c1 = encrypt(n, g, str2int("pascal_paillier"))
        conn.sendline(int2hexstr(c1))
        print(conn.recvline())
        print(conn.recvline())
        return

    s1 = str2int(sys.argv[1])
    s2 = -1 * str2int("Takoyakitabetai")

    c1 = encrypt(n, g, s1)
    c2 = encrypt(n, g, s2)

    c = (c1 * c2) % (n*n)

    conn.sendline(int2hexstr(c))
    print(conn.recvuntil("!"))

if __name__ == '__main__':
    main()
