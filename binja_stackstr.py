from binaryninja import *
from typing import *
from ctypes import Structure, c_ulonglong

keys = set()
strings = {}
targets = []

cb: BasicBlock = current_basic_block


class uint128_t(Structure):
    _fields_ = [("lo", c_ulonglong), ("hi", c_ulonglong)]


def decode(value: str) -> Union[str, None]:
    return bytearray.fromhex(value[2:]).decode("utf-8")[::-1]


def decrypt(var: int, reg: int) -> Union[str, None]:
    hi = var.hi ^ reg.hi
    lo = var.lo ^ reg.lo

    hex_hi = hex(hi)
    hex_lo = hex(lo)

    try:
        if lo and hi:
            return decode(hex_lo) + decode(hex_hi)
        return decode(hex_hi) if hi else decode(hex_lo) if lo else None
    except Exception:
        return None


for insn in cb.view.mlil_instructions:
    if insn.operation == MediumLevelILOperation.MLIL_SET_VAR and isinstance(
        insn.src, mediumlevelil.MediumLevelILXor
    ):
        if not insn.dest.name.startswith("zmm"):
            continue

        right = insn.src.right
        index = insn.src.instr_index

        xor_loc = insn.address

        for prev_insn_idx in range(index, index - 7, -1):
            prev = list(cb.view.mlil_instructions)[prev_insn_idx]

            if not isinstance(prev.src, mediumlevelil.MediumLevelILConst):
                continue

            match prev.operation:
                case MediumLevelILOperation.MLIL_SET_VAR_FIELD:
                    keys.add(prev.src.constant)

                case MediumLevelILOperation.MLIL_SET_VAR:
                    key = prev.dest.name[:5]

                    if key not in strings:
                        strings[key] = []

                    strings[key].append(prev.src.constant)


keys = list(keys)
key = uint128_t(keys[1], keys[0])

for s in strings.values():
    string = decrypt(uint128_t(s[1], s[0]), key)

    print(string, hex(xor_loc))

    if string:
        bv.set_comment_at(xor_loc, f"str: {string}")
