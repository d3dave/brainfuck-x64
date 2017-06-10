import sys
import cough

RELOC_ADDR64 = 0x01
RELOC_REL32 = 0x4

MEMORY_SIZE = 0x400

READ_CELL = b'\x8B\x0B'  # mov ecx, [rbx]
RET = b'\xC3'

PROC_ENT = b'\x55\x48\x89\xE5'  # push rbp; mov rbp, rsp TODO: replace with enter?
PROC_RET = b'\x48\x89\xEC\x5D' + RET  # mov rsp, rbp; pop rbp; ret TODO: replace with leave?

STACK_SIZE = (0x20).to_bytes(1, 'little')  # Windows mandates at least 0x20 stack space for callee
ALLOC_STACK = b'\x48\x83\xEC' + STACK_SIZE
FREE_STACK = b'\x48\x83\xC4' + STACK_SIZE
INIT_PTR = b'\x48\xBB' + b'\x00' * 8  # mov rbx, bf_mem

op_next = b'\x48\x83\xC3\x08'  # add rbx, 8
op_prev = b'\x48\x83\xEB\x08'  # sub rbx, 8
op_inc = b'\x48\xFF\x03'  # inc [rbx]
op_dec = b'\x48\xFF\x0B'  # dec [rbx]
op_out = READ_CELL + b'\xE8' + b'\x00' * 4  # call putchar
op_in = b'\xE8' + b'\x00' * 4 + b'\x48\x89\x03'  # call getchar; mov [rbx], ax
op_loop_open = READ_CELL + b'\x48\x85\xC9\x0F\x84\x00\x00\x00\x00'  # test rcx; jz
op_loop_close = READ_CELL + b'\x48\x85\xC9\x0F\x85\x00\x00\x00\x00'  # test rcx; jnz

OPS = {
    '>': op_next,
    '<': op_prev,
    '+': op_inc,
    '-': op_dec,
    '.': op_out,
    ',': op_in,
    '[': op_loop_open,
    ']': op_loop_close
}


def main():
    stdin = sys.stdin.read()
    stdin_iter = iter(stdin)
    instrs = []
    instrs.append(PROC_ENT)
    instrs.append(ALLOC_STACK)
    instrs.append(INIT_PTR)

    loop_starts = []
    total_len = 0
    for c in stdin_iter:
        if c not in OPS:
            continue

        op = OPS[c]
        instrs.append(op)
        total_len += len(op)
        if c == '[':
            loop_starts.append((len(instrs) - 1, total_len))
        elif c == ']':
            start_i, start_loc = loop_starts.pop()
            d = total_len - start_loc
            instrs[start_i] = instrs[start_i][:-4] + d.to_bytes(4, 'little', signed=True)
            instrs[-1] = instrs[-1][:-4] + (-d).to_bytes(4, 'little', signed=True)

    instrs.append(FREE_STACK)
    instrs.append(PROC_RET)
    buf = assemble(instrs)
    with open('main.obj', 'wb') as obj_file:
        obj_file.write(buf)


def assemble(instructions):
    module = cough.ObjectModule()

    getchar_symbol = cough.SymbolRecord(b'getchar', storage_class=cough.StorageClass.EXTERNAL)
    getchar_symbol.value = 0
    module.symbols.append(getchar_symbol)

    putchar_symbol = cough.SymbolRecord(b'putchar', storage_class=cough.StorageClass.EXTERNAL)
    putchar_symbol.value = 0
    module.symbols.append(putchar_symbol)

    mem_section = cough.Section(
        b'bf_mem',
        cough.SectionFlags.MEM_READ | cough.SectionFlags.MEM_WRITE | cough.SectionFlags.CNT_UNINITIALIZED_DATA)
    mem_section.size_of_raw_data = MEMORY_SIZE
    module.sections.append(mem_section)

    mem_sym = cough.SymbolRecord(b'bf_mem', section_number=1, storage_class=cough.StorageClass.STATIC)
    mem_sym.value = 0
    module.symbols.append(mem_sym)

    text_section = cough.Section(b'.text', flags=cough.SectionFlags.MEM_EXECUTE)
    text_section.data = b''
    reloc_insts = [op_in, op_out]
    for inst in instructions:
        p = len(text_section.data)
        if inst in reloc_insts:
            reloc = cough.Relocation()
            reloc.type = RELOC_REL32
            reloc.symbol_table_index = reloc_insts.index(inst)
            reloc.virtual_address = p + (len(READ_CELL) if inst == op_out else 0) + 1
            text_section.relocations.append(reloc)
            text_section.number_of_relocations += 1
        text_section.data += inst
    text_section.size_of_raw_data = len(text_section.data)

    bf_mem_reloc = cough.Relocation()
    bf_mem_reloc.virtual_address = len(PROC_ENT) + len(ALLOC_STACK) + 2
    bf_mem_reloc.type = RELOC_ADDR64
    bf_mem_reloc.symbol_table_index = 2  # bf_mem
    text_section.relocations.append(bf_mem_reloc)
    text_section.number_of_relocations += 1

    module.sections.append(text_section)

    main_symbol = cough.SymbolRecord(b'main', section_number=2, storage_class=cough.StorageClass.EXTERNAL)
    main_symbol.value = 0
    module.symbols.append(main_symbol)

    return module.get_buffer()


main()
