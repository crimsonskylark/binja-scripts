from binaryninja import *
from typing import *
from ctypes import Structure, c_uint64

DEFAULT_ALIGN: int = 8
MAX_VTABLE_ENTRIES: int = 255 * 8
SKIP_DTOR_ONLY: bool = True
SKIP_INHERITANCE: bool = True

_bv: BinaryView = bv

rdata: Section = _bv.sections[".rdata"]

def _filter_vtable_entry(entry: int) -> bool:
    pred: List[bool] = [
        SKIP_INHERITANCE and (entry >= rdata.start and entry <= rdata.end),
        _bv.get_function_at(entry) is None,
    ]

    if any(pred):
        return False

    return True


class CommonLayout(Structure):
    _fields_ = [
        ("_destructor", c_uint64),
        ("_size", c_uint64),
        ("_align", c_uint64),
    ]

    @property
    def destructor(self):
        return self._destructor

    @property
    def size(self):
        return self._size

    @property
    def align(self):
        return self._align


block_size: int = ctypes.sizeof(CommonLayout)

for b in range(0, rdata.length, block_size):
    try:
        addr: int = rdata.start + b

        layout = CommonLayout.from_buffer_copy(_bv.read(addr, block_size))

        fn: Function | None = _bv.get_function_at(layout.destructor)

        if not fn:
            continue

        if layout.align == DEFAULT_ALIGN and layout.size < MAX_VTABLE_ENTRIES:
            vft_count_no_dtor: int = layout.size - 8

            vfs: List[int] = list(
                filter(
                    _filter_vtable_entry,
                    [
                        _bv.read_pointer(addr + block_size + disp)
                        for disp in range(0, vft_count_no_dtor, 8)
                    ],
                )
            )

            # Skip destructor-only vtables..
            if not vfs and SKIP_DTOR_ONLY:
                continue

            print(
                f"found potential vtable @ {addr:x} | fns: {[_bv.get_function_at(vf).name for vf in vfs]}"
            )
    except ValueError:
        continue
