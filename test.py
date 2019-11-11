import binascii
from assembler import *
from disassembler import *
from il import *
from register_allocator import *

class BasicBlock:
    def __init__(self, code=None):
        self.code = code
        if code:
            self.address = code[0].address
        else:
            self.address = None
        self.predecessors = set()
        self.successors = set()

    def add_successor(self, other):
        self.successors.add(other)
        other.predecessors.add(self)

    @staticmethod
    def code_to_blocks(code):
        # TODO: clean this way the fuck up
        boundaries = set()
        blocks = {}
        basic_blocks = []

        for i, instruction in enumerate(code):
            if EQ <= instruction.opcode <= GEF:
                boundaries.add(instruction.address)
                boundaries.add(instruction.operand-1)
            elif instruction.opcode == JUMP:
                boundaries.add(instruction.address)
                if instruction.operand is not None:
                    boundaries.add(instruction.operand-1)
        boundaries.add(code[-1].address)

        block = BasicBlock()
        start = 0
        for i, instruction in enumerate(code):
            if instruction.address in boundaries:
                next_block = BasicBlock()
                if instruction is not code[-1]:
                    block.add_successor(next_block)
                block.code = code[start:i+1]
                block.address = code[start].address
                blocks[block.address] = block
                basic_blocks.append(block)
                block = next_block
                start = i + 1

        for block in basic_blocks:
            last_instruction = block.code[-1]
            if EQ <= last_instruction.opcode <= GEF:
                block.add_successor(blocks[last_instruction.operand])
            elif last_instruction.opcode == JUMP:
                if last_instruction.operand is not None:
                    block.add_successor(blocks[last_instruction.operand])

        return basic_blocks

class CodeGenerator:
    def __init__(self):
        self.asm = Assembler()
        self.gprs = [EBX, ECX, EDX, ESI, EDI]

    def generate(self, sub):
        # reset register use for every sub
        self.regs = RegAllocator(self.spill, self.unspill, len(self.gprs))

        bbs = BasicBlock.code_to_blocks(sub)

        bb_labels = {}
        for bb in bbs:
            bb_labels[bb] = self.asm.label()

        for bb in bbs:
            bb_labels[bb].bind()
            self.successor_labels = [bb_labels[successor] for successor in bb.successors]
            il = build_il(bb)
            for ins in il:
                self.visit(ins)

    def reg_num(self, reg):
        return self.gprs[reg.num]

    def spill(self, reg):
        print(f'spill {reg}')

    def unspill(self, reg):
        print(f'unspill {reg}')

    def visit(self, node):
        method = 'visit_' + mnemonics[node.opcode]
        visitor = getattr(self, method, self.generic_visit)
        return visitor(node)

    def generic_visit(self, node):
        raise Exception(f'No visit_{mnemonics[node.opcode]} method')

    def visit_ENTER(self, node):
        self.asm.push(EBP)
        self.asm.mov(EBP, ESP)
        self.asm.subimm(ESP, node.value)

    def visit_LEAVE(self, node):
        assert len(node.children) <= 1
        if len(node.children) == 1:
            reg = self.visit(node.child)
            self.asm.mov(EAX, self.reg_num(reg))
            reg.free()
        self.asm.mov(ESP, EBP)
        self.asm.pop(EBP)
        self.asm.ret()

    def visit_ARG(self, node):
        reg = self.visit(node.child)
        self.asm.bp()
        reg.free()

    def visit_CALL(self, node):
        reg = self.visit(node.child)
        self.asm.call_reg(self.reg_num(reg))
        self.asm.mov(self.reg_num(reg), EAX)
        return reg

    def visit_PUSH(self, node):
        reg = self.regs.new()
        self.asm.load_const(self.reg_num(reg), 0)
        return reg

    def visit_CONST(self, node):
        reg = self.regs.new()
        self.asm.load_const(self.reg_num(reg), node.value)
        return reg

    def visit_LOCAL(self, node):
        reg = self.regs.new()
        self.asm.local(self.reg_num(reg), node.value)
        return reg

    def visit_LOAD4(self, node):
        reg = self.visit(node.child)
        self.asm.load(self.reg_num(reg), self.reg_num(reg))
        return reg

    def visit_STORE4(self, node):
        dest = self.visit(node.left)
        src = self.visit(node.right)
        self.asm.store(self.reg_num(dest), self.reg_num(src))
        dest.free()
        src.free()

    def visit_ADD(self, node):
        dest = self.visit(node.left)
        src = self.visit(node.right)
        self.asm.add(self.reg_num(dest), self.reg_num(src))
        src.free()
        return dest

    def visit_LSH(self, node):
        dest = self.visit(node.left)
        shift = self.visit(node.right)

        self.asm.push(ECX)
        self.asm.mov(ECX, self.reg_num(shift))
        self.asm.shl_cl(self.reg_num(dest))
        self.asm.pop(ECX)

        shift.free()
        return dest

    def visit_MULI(self, node):
        dest = self.visit(node.left)
        src = self.visit(node.right)
        self.asm.bp()
        src.free()
        return dest

    def visit_JUMP(self, node):
        reg = self.visit(node.child)
        # TODO convert to instruction index by loading from global array?
        # could also optimize here if child is CONST (or would a separate pass with other optimizations be better?)
        self.asm.jmp_reg(self.reg_num(reg))
        reg.free()

    def do_conditional_jump(self, node):
        self.asm.bp()
        left = self.visit(node.left)
        right = self.visit(node.right)
        self.asm.jmp(self.successor_labels[0])
        self.asm.jmp(self.successor_labels[1])
        left.free()
        right.free()

    def visit_NE(self, node):
        self.do_conditional_jump(node)

    def visit_LTI(self, node):
        self.do_conditional_jump(node)

    def visit_GTI(self, node):
        self.do_conditional_jump(node)

def main():
    with open('qagame.qvm', 'rb') as f:
        magic             = f.read(4)
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

        subs = {}
        start = 0
        for i, instruction in enumerate(code):
            if i > 0 and instruction.opcode == ENTER:
                subs[start] = code[start:i]
                start = i
        subs[start] = code[start:i]

    cg = CodeGenerator()
    cg.generate(subs[0])
    cg.asm.fixup_labels()
    print(binascii.hexlify(cg.asm.code).decode())

if __name__ == '__main__':
    main()
