import hashlib
import binascii
import re
import z3

s = bytearray("\x00" * 85, "utf-8")
word_ = [bytes([i, j]) for i in range(256) for j in range(256)]


def main():
    pattern = re.compile(r"uint32\((\d+)\)\s*([+\-^])\s*(\d+)\s*==\s*(\d+)")

    with open("new_aray.bin", "r") as file:
        lines = file.readlines()

    for line in lines:
        line = line.strip()
        match = pattern.match(line)
        if match:
            offset = match.group(1)
            op = match.group(2)
            lvalue = match.group(3)
            rvalue = match.group(4)
            # print(
            #     f"Offset: {offset}, Operation: {op}, Left Value: {lvalue}, Right Value: {rvalue}"
            # )
            handle_math(int(offset), op, int(lvalue), int(rvalue))

    for i in word_:
        if hashlib.md5(i).hexdigest() == "89484b14b36a8d5329426a3d944d2983":
            s[0:2] = i
            # print(f"0: {i}")
        elif hashlib.md5(i).hexdigest() == "f98ed07a4d5f50f7de1410d905f1477f":
            s[76:78] = i
            # print(f"76: {i}")
        elif hashlib.md5(i).hexdigest() == "657dae0913ee12be6fb2a6f687aae1c7":
            s[50:52] = i
            # print(f"50: {i}")
        elif hashlib.md5(i).hexdigest() == "738a656e8e8ec272ca17cd51e12f558b":
            s[32:34] = i
            # print(f"32: {i}")
        elif (
            hashlib.sha256(i).hexdigest()
            == "403d5f23d149670348b147a15eeb7010914701a7e99aad2e43f90cfa0325c76f"
        ):
            s[14:16] = i
            # print(f"14: {i}")
        elif (
            hashlib.sha256(i).hexdigest()
            == "593f2d04aab251f60c9e4b8bbc1e05a34e920980ec08351a18459b2bc7dbf2f6"
        ):
            s[56:58] = i
            # print(f"56: {i}")
        elif binascii.crc32(i) == 0x61089C5C:
            s[8:10] = i
            # print(f"9: {i}")
        elif binascii.crc32(i) == 0x5888FC1B:
            s[34:36] = i
            # print(f"34: {i}")
        elif binascii.crc32(i) == 0x66715919:
            s[63:65] = i
            # print(f"63: {i}")
        elif binascii.crc32(i) == 0x7CAB8D64:
            s[78:80] = i
            # print(f"78: {i}")
    s[36] = solve_unknowns(36)
    s[45] = solve_unknowns(45)
    s[58] = solve_unknowns(58)
    s[65] = solve_unknowns(65)
    # for i in range(len(s)):
        # print(f"{i}: {chr(s[i])}")

def handle_math(offset, op, lvalue, rvalue):
    res = 0
    if op == "-":
        res = rvalue + lvalue
    elif op == "+":
        res = rvalue - lvalue
    elif op == "^":
        res = rvalue ^ lvalue
    res_bytes = res.to_bytes((res.bit_length() + 7) // 8, "little")
    res_bytes = res_bytes.ljust(5, b"\x00")[:4]
    # print(f"{offset}: {res_bytes}")
    s[offset : offset + 5] = res_bytes


def solve_unknowns(flag):
    x = z3.BitVec("x", 8)
    s = z3.Solver()
    if flag == 36:
        s.add(
            x + 4 == 72,
            x > 11,
            x & 128 == 0,
            x % 22 < 22,
            85 ^ x != 95,
            85 ^ x != 6,
            #  x < 146 ,
        )
    elif flag == 45:
        s.add(
            x ^ 9 == 104,
            x & 128 == 0,
            #  x < 136 ,
            85 ^ x != 146,
            x % 17 < 17,
            85 ^ x != 19,
            x > 17,
        )
    elif flag == 58:
        s.add(
            x + 25 == 122,
            x > 30,
            # x < 146 ,
            x % 14 < 14,
            85 ^ x != 12,
            x & 128 == 0,
            85 ^ x != 77,
        )
    elif flag == 65:
        s.add(
            x - 29 == 70,
            85 ^ x != 28,
            x > 1,
            85 ^ x != 215,
            x & 128 == 0,
            # x < 149,
            x % 22 < 22,
        )
    if s.check() == z3.sat:
        return s.model()[x].as_long()


if __name__ == "__main__":
    main()
    print(s)
    # bytearray(b'ru\x00e fl\x00reon { s\x00ring\x00: $f\x00\x00 "1RuleADayK33p$Malw4r3Aw4y@flare-on.com" cond $ion:')
    # flag: 1RuleADayK33p$Malw4r3Aw4y@flare-on.com



## extract clean lines
# import re

# patterns = [rf'\({i}\)' for i in range(85)]

# with open('aray.yara', 'r') as file:
#     lines = file.readlines()
# matching_lines = [line for line in lines if any(re.search(pattern, line) for pattern in patterns)]

# sorted_lines = sorted(matching_lines, key=lambda line: int(re.search(r'\((\d+)\)', line).group(1)))

# with open('new_aray.bin','w+') as file:
#     for line in sorted_lines:
#         file.write(line)

## generate variables
# for i in range(85):
#     print(f"x_{i} = z3.BitVec('x_{i}',8)")
