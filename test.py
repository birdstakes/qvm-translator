import argparse
import sys
from codegen import *
from disassembler import *
from ir import *

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input', help='the qvm to translate')
    parser.add_argument('output', help='the resulting x86 code')
    parser.add_argument('--map', help='a q3asm map file')
    parser.add_argument('--symbols', help='dump symbols to SYMBOLS')
    parser.add_argument('--data', help='dump the data section to DATA')
    parser.add_argument('--lit',  help='dump the lit section to LIT')
    args = parser.parse_args()

    with open(args.input, 'rb') as f:
        magic             = int.from_bytes(f.read(4), 'little')
        if magic != 0x12721444:
            sys.exit('Not a valid qvm file')
        instruction_count = int.from_bytes(f.read(4), 'little')
        code_offset       = int.from_bytes(f.read(4), 'little')
        code_size         = int.from_bytes(f.read(4), 'little')
        data_offset       = int.from_bytes(f.read(4), 'little')
        data_size         = int.from_bytes(f.read(4), 'little')
        lit_size          = int.from_bytes(f.read(4), 'little')
        bss_size          = int.from_bytes(f.read(4), 'little')

        f.seek(code_offset)
        code = disassemble(f.read(code_size))
        code = code[:instruction_count] # strip off any padding that may have been there

        f.seek(data_offset)
        data = f.read(data_size)

        f.seek(data_offset + data_size)
        lit = f.read(lit_size)

        subs = []
        start = 0
        for i, instruction in enumerate(code):
            if i > 0 and instruction.opcode == ENTER:
                subs.append(code[start:i])
                start = i
        subs.append(code[start:])

    # need to save clobbered registers?
    # decompilers probably won't care

    # hex-rays won't decompile sse stuff... need to use x87?
    # ghidra does though

    cg = CodeGenerator()
    for i, sub in enumerate(subs):
        basic_blocks = build_ir(sub)
        cg.generate(basic_blocks)
    cg.finish()

    with open(args.output, 'wb') as f:
        f.write(cg.asm.code)

    qvm_map = []

    if args.map:
        with open(args.map, 'rb') as f:
            for line in f:
                type, address, name = line.split()
                if int(type) == 0:
                    qvm_map.append((int(address, 16), name.decode()))

    if args.symbols:
        with open(args.symbols, 'wb') as f:
            for address, name in qvm_map:
                if address in cg.sub_labels:
                    label = cg.sub_labels[address]
                    assert label.address is not None
                    f.write(f'{name} {label.address:#x}\n'.encode())

            f.write(f'__memcpy {cg.memcpy_label.address:#x}\n'.encode())
            f.write(f'__instruction_addresses {cg.instruction_addresses_label.address:#x}\n'.encode())

    if args.data:
        with open(args.data, 'wb') as f:
            f.write(data)

    if args.lit:
        with open(args.lit, 'wb') as f:
            f.write(lit)

    print(f'data segment: offset = {0:#8x} size = {data_size:#8x}')
    print(f'lit  segment: offset = {data_size:#8x} size = {lit_size:#8x}')
    print(f'bss  segment: offset = {data_size+lit_size:#8x} size = {bss_size:#8x}')

if __name__ == '__main__':
    main()
