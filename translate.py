import os
import sys
import xml.etree.cElementTree as ET
from pathlib import Path
from codegen import *
from disassembler import *
from ir import *

def main(args):
    if len(args) < 2:
        sys.exit(f'usage: {args[0]} [qvm files ...] [map files ...]')

    qvms = []
    maps = []
    for arg in args[1:]:
        arg = Path(arg)
        if arg.suffix == '.qvm':
            qvms.append(arg)
        elif arg.suffix == '.map':
            maps.append(arg)
        else:
            sys.exit(f'unrecognized file type {arg.suffix}')

    syscall_maps = {
        'qagame': 'g_syscalls.map',
        'cgame': 'cg_syscalls.map',
        'ui': 'ui_syscalls.map'
    }

    for qvm_path in qvms:
        syscalls = syscall_maps.get(qvm_path.stem)
        if syscalls is not None:
            syscalls_path = Path(__file__).resolve().parent.joinpath(syscalls)
            map_paths = [syscalls_path] + maps
        else:
            map_paths = maps

        translate(
            qvm_path,
            map_paths,
            qvm_path.with_suffix('.xml'),
            qvm_path.with_suffix('.bytes')
        )

def translate(qvm_path, map_paths, xml_path, bytes_path):
    with open(qvm_path, 'rb') as f:
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
        code = code[:instruction_count] # strip off padding

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

    cg = CodeGenerator()
    for i, sub in enumerate(subs):
        basic_blocks = build_ir(sub)
        cg.generate(basic_blocks)
    cg.finish()

    symbols = {}

    for map_path in map_paths:
        with open(map_path, 'rb') as f:
            for line in f:
                type, address, name = line.split()
                type = int(type)
                address = int(address, 16)
                name = name.decode()
                if type == 0 and address in cg.sub_labels:
                    address = cg.sub_labels[address].address
                    assert address is not None
                    symbols[name] = address
                elif type == 1:
                    symbols[name] = address
                elif type == 2:
                    symbols[name] = data_size + address
                elif type == 3:
                    symbols[name] = data_size + lit_size + address

    symbols['vmMain'] = cg.asm.base
    symbols['__memcpy'] = cg.memcpy_label.address
    symbols['__instruction_addresses'] = cg.instruction_addresses_label.address

    program = ET.Element('PROGRAM')

    # all of this is needed for ghidra to detect the right language
    ET.SubElement(
        program,
        'INFO_SOURCE',
        TOOL='IDA-Pro 7.00 XML plugin v5.0.1 (Python) SDK 700'
    )
    ET.SubElement(
        program,
        'PROCESSOR',
        NAME='metapc',
        ENDIAN='little',
        ADDRESS_MODEL='32-bit'
    )
    ET.SubElement(program, 'COMPILER', NAME='gcc')

    memory_map = ET.SubElement(program, 'MEMORY_MAP')

    maps = (
        ('code', cg.asm.base, 'rx', cg.asm.code),
        ('data', 0,  'rw', data),
        ('lit', data_size, 'r', lit),
        ('bss', data_size + lit_size, 'rw', b'\x00'*bss_size),
    )

    with open(bytes_path, 'wb') as f:
        for name, start_addr, permissions, contents in maps:
            length = len(contents)
            file_offset = f.tell()
            f.write(contents)

            section = ET.SubElement(
                memory_map,
                'MEMORY_SECTION',
                NAME=name,
                START_ADDR=f'{start_addr:#X}',
                LENGTH=f'{length:#X}',
                PERMISSIONS=permissions,
            )
            ET.SubElement(
                section,
                'MEMORY_CONTENTS',
                START_ADDR=f'{start_addr:#X}',
                FILE_NAME=bytes_path.name,
                FILE_OFFSET=f'{file_offset:#X}',
                LENGTH=f'{length:#X}'
            )

    code = ET.SubElement(program, 'CODE')
    ET.SubElement(
        code,
        'CODE_BLOCK',
        START=f'{cg.asm.base:#X}',
        END=f'{cg.instruction_addresses_label.address:#X}'
    )

    program_entry_points = ET.SubElement(program, 'PROGRAM_ENTRY_POINTS')
    ET.SubElement(
        program_entry_points,
        'PROGRAM_ENTRY_POINT',
        ADDRESS=f'{cg.asm.base:#X}'
    )

    symbol_table = ET.SubElement(program, 'SYMBOL_TABLE')
    for name, address in symbols.items():
        ET.SubElement(symbol_table, 'SYMBOL', ADDRESS=f'{address:#X}', NAME=name)

    comments = ET.SubElement(program, 'COMMENTS')
    for qvm_start in cg.sub_labels:
        start = cg.sub_labels[qvm_start].address
        comment = ET.SubElement(
            comments,
            'COMMENT',
            ADDRESS=f'{start:#X}',
            TYPE='plate'
        )
        comment.text = f'QVM address: {qvm_start:#x}'

    with open(xml_path, 'wb') as f:
        f.write(b'<?xml version="1.0" standalone="yes"?>\n')
        f.write(b'<?program_dtd version="1"?>\n')
        f.write(ET.tostring(program))

if __name__ == '__main__':
    main(sys.argv)
