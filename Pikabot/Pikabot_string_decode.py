## Pikabot stack strings decoder
## This script is based on OALABS Research
## https://research.openanalysis.net/pikabot/yara/config/loader/2023/02/26/pikabot.html
## This script from my blog https://d01a.github.io/pikabot/ so it's old version (2023-07-31)

import ctypes

import idc
import idaapi
import idautils


def get_operand_offset(ea):
    op_offset = idc.get_operand_value(ea, 0)
    return ctypes.c_int(op_offset).value


def get_second_operand(ea):
    op_offset = idc.get_operand_value(ea, 1)
    return ctypes.c_uint(op_offset).value


def get_second_operand_short(ea):
    op_offset = idc.get_operand_value(ea, 1)
    return ctypes.c_ushort(op_offset).value


def get_bitwise_op(ea, block_start_ea):
    while (
        idc.print_insn_mnem(ea) != "xor"
        and idc.print_insn_mnem(ea) != "add"
        and idc.print_insn_mnem(ea) != "and"
        and idc.print_insn_mnem(ea) != "sub"
    ) and ea > block_start_ea:
        ea = idc.prev_head(ea)
    return ea


def bitwise_and_bytes(a, b):
    result_int = int.from_bytes(a, byteorder="little") & int.from_bytes(b, byteorder="little")
    result_int = result_int & 0x00FF
    return result_int.to_bytes(1, byteorder="little")


def bitwise_sub_bytes(a, b):
    result_int = int.from_bytes(a, byteorder="little") - int.from_bytes(b, byteorder="little")
    result_int = result_int & 0x00FF
    # print(result_int)
    return result_int.to_bytes(1, byteorder="little")


def bitwise_add_bytes(a, b):
    result_int = int.from_bytes(a, byteorder="little") + int.from_bytes(b, byteorder="little")
    result_int = result_int & 0x00FF
    return result_int.to_bytes(1, byteorder="little")


def bitwise_xor_bytes(a, b):
    result_int = int.from_bytes(a, byteorder="little") ^ int.from_bytes(b, byteorder="little")
    result_int = result_int & 0x00FF
    return result_int.to_bytes(1, byteorder="little")


def set_comment(address, text):
    idc.set_cmt(address, text, 0)


def set_hexrays_comment(address, text):
    """
    set comment in decompiled code
    """
    cfunc = idaapi.decompile(address)
    tl = idaapi.treeloc_t()
    tl.ea = address
    tl.itp = idaapi.ITP_SEMI
    cfunc.set_user_cmt(tl, text)
    cfunc.save_user_cmts()


def is_valid_cmp(ea):
    if idc.print_insn_mnem(ea) == "cmp":
        if idc.get_operand_type(ea, 0) == 1 and idc.get_operand_type(ea, 1) == 5:
            return True
    return False


def parse_fn(fn):
    out = []
    func = ida_funcs.get_func(fn)  # get function pointer
    func_fc = list(idaapi.FlowChart(func, flags=idaapi.FC_PREDS))  # get function flowchart object (list of blocks)

    for block_index in range(len(func_fc)):
        block = func_fc[block_index]
        last_inst = idc.prev_head(block.end_ea)

        # TODO: ADD "cmp ecx, <const>" instruction to the comparison
        if idc.print_insn_mnem(last_inst) == "jl" and is_valid_cmp(idc.prev_head(last_inst)):
            stack_end_ea = block.end_ea
            prev_block = func_fc[block_index - 1]
            stack_start_ea = prev_block.start_ea
            first_BB_end = prev_block.end_ea
            # get stack offset
            inst_ptr = last_inst
            while inst_ptr >= block.start_ea:
                inst_ptr = idc.prev_head(inst_ptr)
                if idc.print_insn_mnem(inst_ptr) == "mov" and get_second_operand(idc.prev_head(inst_ptr)) <= 255:
                    out.append(
                        {
                            "start": stack_start_ea,
                            "end": stack_end_ea,
                            "first_BB_end": first_BB_end,
                            "bitwise_op": get_bitwise_op(inst_ptr, block.start_ea),
                        }
                    )
                    break
    return out


# get the addresses of stack strings
def get_all_strings():
    stack_strings = []
    for f in idautils.Functions():
        out = parse_fn(f)
        stack_strings += out
    return stack_strings


def decode_strings(stack_strings):
    strings = {}
    for ss in stack_strings:
        try:
            out = emulate(ss.get("start"), ss.get("end"), ss.get("first_BB_end"), ss.get("bitwise_op"))
            print(f"{hex(ss.get('start'))}: {out.decode('utf-8',errors='ignore')}")
            strings[ss.get("start")] = out.decode("utf-8", errors="ignore")
        except Exception as e:
            print(e)
            print(f"Failed decoding: {hex(ss.get('start'))}")
    return strings


def ss_decrypt(operation, key, byte_str):
    output = b""
    for i in byte_str:
        i = i.to_bytes(1, byteorder="little")
        if operation == "xor":
            output += bitwise_xor_bytes(i, key)
        elif operation == "add":
            output += bitwise_add_bytes(i, key)
        elif operation == "and":
            output += bitwise_and_bytes(i, key)
        elif operation == "sub":
            output += bitwise_sub_bytes(i, key)
    return output


def get_byte_string(start, end, str_len):
    byte_str = b""
    inst_ptr = end
    while inst_ptr >= start:
        inst_ptr = idc.prev_head(inst_ptr)
        if idc.print_insn_mnem(inst_ptr) == "mov":
            if idc.get_operand_type(inst_ptr, 1) == 5:
                dtype_val = idautils.DecodeInstruction(inst_ptr)
                if ida_ua.get_dtype_size(dtype_val.Op1.dtype) == 2:
                    temp = get_second_operand_short(inst_ptr)
                else:
                    temp = get_second_operand(inst_ptr)
                temp = temp.to_bytes(4, byteorder="little")
                # print(f"str: {temp}")
                # insert at the beginning of the string.
                temp_list = list(temp)
                byte_str_list = list(byte_str)
                temp_list.extend(byte_str_list)
                byte_str = bytes(temp_list)
    byte_str = byte_str.replace(b"\x00", b"")
    print(f"byte_str: {byte_str}")
    return byte_str


def emulate(start, end, first_BB_end, bitwise_op_addr):
    last_inst = idc.prev_head(end)
    operation = idc.print_insn_mnem(bitwise_op_addr)
    key = get_second_operand(bitwise_op_addr)
    print(f"address:{hex(bitwise_op_addr)} key: {hex(key)}")
    key = key.to_bytes(1, byteorder="little")
    str_len = get_second_operand(idc.prev_head(last_inst))
    byte_str = get_byte_string(start, first_BB_end, str_len)
    string = ss_decrypt(operation, key, byte_str)
    return string


def main():
    stack_strings = get_all_strings()
    strings = decode_strings(stack_strings)
    for k, v in strings.items():
        set_comment(k, v)
        ## if you have hexrays decompiler, you can use this function to set comment in decompiled code
        # set_hexrays_comment(k,v)


if __name__ == "__main__":
    main()
