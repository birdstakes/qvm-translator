import io
from opcodes import *

class Instruction:
    def __init__(self, address, opcode, operand=None):
        self.address = address
        self.opcode = opcode
        self.operand = operand

    def __repr__(self):
        if self.operand:
            return f'{self.address:#08x}: {mnemonics[self.opcode]} {self.operand:#x}'
        else:
            return f'{self.address:#08x}: {mnemonics[self.opcode]}'

    __str__ = __repr__

def disassemble(code, address=0):
    code = io.BytesIO(code)
    instructions = []

    while True:
        opcode = code.read(1)
        if opcode == b'':
            break

        opcode = ord(opcode)
        instruction = Instruction(address, opcode)

        if opcode in (ENTER, LEAVE, CONST, LOCAL, BLOCK_COPY) or EQ <= opcode <= GEF:
            instruction.operand = int.from_bytes(code.read(4), 'little')

        elif opcode == ARG:
            instruction.operand = int.from_bytes(code.read(1), 'little')

        elif opcode == JUMP and instructions[-1].opcode == CONST:
            instruction.operand = instructions[-1].operand

        instructions.append(instruction)
        address += 1

    return instructions
