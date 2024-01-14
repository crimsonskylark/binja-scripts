from binaryninja import *
from ctypes import Structure, c_ulonglong

_bv: BinaryView = bv

cf: MediumLevelILFunction = current_function.medium_level_il


class uint128_t(Structure):
    _fields_ = [("_lo", c_ulonglong), ("_hi", c_ulonglong)]

    @property
    def hi(self):
        return self._hi

    @property
    def lo(self):
        return self._lo


def decode(value: str) -> Union[str, None]:
    return bytearray.fromhex(value[2:]).decode("utf-8")[::-1]


def decrypt(var: uint128_t, reg: uint128_t) -> Union[str, None]:
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


def stack_offset_from_name(name: str) -> int:
    return -int(name.split("_")[1], 16)


_bv.begin_undo_actions()

for bb_idx, bb in enumerate(cf.basic_blocks):
    bb_str: List[str] = []

    for insn in bb:
        match insn.operation:
            case MediumLevelILOperation.MLIL_SET_VAR:
                op: MediumLevelILXor | MediumLevelILConst | Any = insn.src
                is_const_assign: bool = isinstance(op, MediumLevelILConst)

                if isinstance(op, MediumLevelILXor):
                    op.left.src.type = "uint64_t[2]"
                    op.right.src.type = "uint64_t[2]"

                    left: Variable = cf.get_var_definitions(op.left.src)[0]
                    right: Variable = op.right.src

                    ofs: int = stack_offset_from_name(left.src.src.name)
                    ofs_2: int = stack_offset_from_name(right.name)

                    value: str = decrypt(
                        uint128_t(
                            *[
                                insn.get_stack_contents(ofs_2, 8).value,
                                insn.get_stack_contents(ofs_2 + 8, 8).value,
                            ]
                        ),
                        uint128_t(
                            *[
                                insn.get_stack_contents(ofs, 8).value,
                                insn.get_stack_contents(ofs + 8, 8).value,
                            ]
                        ),
                    )

                    if not value:
                        continue

                    try:
                        op.left.src.name = f"{value}_1"
                        op.right.src.name = f"{value}_2"
                    except AttributeError:
                        pass

                    bb_str.append(value)

            case MediumLevelILOperation.MLIL_STORE:
                if not isinstance(insn.dest, MediumLevelILConstPtr):
                    continue

                fn_name: str = bb_str[0]

                if len(bb_str) > 1:
                    for s in bb_str[1:]:
                        try:
                            fn_name += str(s.encode("ascii"), encoding="ascii")
                        except UnicodeDecodeError:
                            pass

                _bv.define_user_symbol(
                    Symbol(
                        SymbolType.FunctionSymbol,
                        addr=insn.dest.constant,
                        short_name=fn_name,
                    )
                )
_bv.commit_undo_actions()
# sub_17688
