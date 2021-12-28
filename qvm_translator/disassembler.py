import io
from .opcodes import Opcode as Op


class Instruction:
    def __init__(self, address, opcode, operand=None):
        self.address = address
        self.opcode = opcode
        self.operand = operand

    def __repr__(self):
        if self.operand:
            return f"{self.address:#08x}: {self.opcode.name} {self.operand:#x}"
        else:
            return f"{self.address:#08x}: {self.opcode.name}"

    __str__ = __repr__


def disassemble(code, address=0):
    code = io.BytesIO(code)
    instructions = []

    while True:
        opcode = code.read(1)
        if opcode == b"":
            break

        opcode = Op(ord(opcode))
        instruction = Instruction(address, opcode)

        if (
            opcode in (Op.ENTER, Op.LEAVE, Op.CONST, Op.LOCAL, Op.BLOCK_COPY)
            or Op.EQ <= opcode <= Op.GEF
        ):
            instruction.operand = int.from_bytes(code.read(4), "little")

        elif opcode == Op.ARG:
            instruction.operand = int.from_bytes(code.read(1), "little")

        elif opcode == Op.JUMP and instructions[-1].opcode == Op.CONST:
            instruction.operand = instructions[-1].operand

        instructions.append(instruction)
        address += 1

    return instructions
