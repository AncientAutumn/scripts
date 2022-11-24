# Usage: python <scriptName.py> <string that you would like to flip with endian swap>


import sys

string = sys.argv[1]
out = ""
temp = ""
index = 0
for char in string:
    temp += char
    index += 1
    if index%4 == 0:
        fwd = ""
        for temp_char in temp:
            fwd = temp_char + fwd
        out += fwd
        temp = ""
print(out)
