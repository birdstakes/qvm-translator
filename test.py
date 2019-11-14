import binascii
import struct
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
        self.predecessors = []
        self.successors = []

    def add_successor(self, other):
        self.successors.append(other)
        other.predecessors.append(self)

    @staticmethod
    def code_to_blocks(code):
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
        self.asm = Assembler(base=0x10000000)
        self.gprs = [EBX, ECX, EDX, ESI, EDI]
        self.sub_labels = {} # for CONST calls

        # for indirect jumps and calls
        self.instruction_addresses = []
        self.instruction_addresses_label = self.asm.label()

        self.invert_conditions = False

    def generate(self, sub):
        # reset register use for every sub
        self.regs = RegAllocator(self.spill, self.unspill, len(self.gprs))
        self.num_spills = 0 # how many slots to allocate for register spilling
        self.arg_size = 0
        self.frame_size = None
        self.frame_size_fixup = None

        sub_address = sub[0].address
        if sub_address not in self.sub_labels:
            self.sub_labels[sub_address] = self.asm.label()
        self.sub_labels[sub_address].bind()

        bbs = BasicBlock.code_to_blocks(sub)

        bb_labels = {}
        for bb in bbs:
            bb_labels[bb] = self.asm.label()

        for bb in bbs:
            bb_labels[bb].bind()
            self.successor_labels = [bb_labels[successor] for successor in bb.successors]
            il = build_il(bb)
            for node in il:
                self.set_instruction_addresses(node)
                reg = self.visit(node)
                if reg is not None:
                    reg.free()

        assert self.frame_size is not None and self.frame_size_fixup is not None
        # i think this is actually too big because of arguments are included
        # in the original frame size, but whatever. we'd have to also fix up
        # spills to fix this instead of putting them at sp - frame_size
        frame_size = self.frame_size + self.arg_size + self.num_spills * 4

        # TODO: this is ugly, maybe add another kind of fixup for arbitrary constants?
        struct.pack_into('<I', self.asm.code, self.frame_size_fixup - self.asm.base, frame_size)

    def finish(self):
        # generate syscall stubs
        for offset, label in self.sub_labels.items():
            if offset >= 0x80000000:
                assert label.address is None
                label.bind()
                self.asm.load_const(EAX, offset)
                self.asm.syscall()
                self.asm.ret()

        # generate instruction address table
        self.asm.align(4)
        self.instruction_addresses_label.bind()
        for instruction_offset in self.instruction_addresses:
            self.asm.emit32(instruction_offset)

        self.asm.fixup_labels()

    def set_instruction_addresses(self, node):
        if node.instruction.address >= len(self.instruction_addresses):
            padding = 1 + node.instruction.address - len(self.instruction_addresses)
            self.instruction_addresses.extend([0] * padding)

        self.instruction_addresses[node.instruction.address] = self.asm.current_address()

        for child in node.children:
            self.set_instruction_addresses(child)

    def reg_num(self, reg):
        return self.gprs[reg.get()]

    def spill(self, reg):
        print(f'spill at {self.asm.current_address():x}')
        if reg.offset >= self.num_spills:
            self.num_spills = reg.offset + 1

        # TODO add `mov [ebp+imm], reg` to assembler?
        self.asm.local(EAX, -(self.frame_size + 4 + reg.offset * 4))
        self.asm.store(EAX, self.reg_num(reg))

    def unspill(self, reg):
        print(f'unspill at {self.asm.current_address():x}')
        # TODO add `mov reg, [ebp+imm]` to assembler?
        self.asm.local(EAX, -(self.frame_size + 4 + reg.offset * 4))
        self.asm.load(self.reg_num(reg), EAX)

    def visit(self, node):
        method = 'visit_' + mnemonics[node.opcode]
        visitor = getattr(self, method, self.generic_visit)
        return visitor(node)

    def generic_visit(self, node):
        raise Exception(f'No visit_{mnemonics[node.opcode]} method')

    def visit_ENTER(self, node):
        self.frame_size = node.value
        self.asm.push(EBP)
        self.asm.mov(EBP, ESP)
        self.frame_size_fixup = self.asm.current_address() + 2
        self.asm.sub_imm(ESP, node.value) 

    def visit_LEAVE(self, node):
        assert len(node.children) <= 1
        if len(node.children) == 1:
            reg = self.visit(node.child)
            self.asm.mov(EAX, self.reg_num(reg))
            reg.free()
        self.asm.mov(ESP, EBP)
        self.asm.pop(EBP)
        self.asm.ret()

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
        self.asm.local(self.reg_num(reg), node.value - self.frame_size)
        return reg

    def do_load(self, node, size):
        reg = self.visit(node.child)
        self.asm.load(self.reg_num(reg), self.reg_num(reg), size=size)
        return reg

    def visit_LOAD1(self, node):
        return self.do_load(node, 8)

    def visit_LOAD2(self, node):
        return self.do_load(node, 16)

    def visit_LOAD4(self, node):
        return self.do_load(node, 32)

    def do_store(self, node, size):
        dest = self.visit(node.left)
        src = self.visit(node.right)
        self.asm.store(self.reg_num(dest), self.reg_num(src), size=size)
        dest.free()
        src.free()

    def visit_STORE1(self, node):
        self.do_store(node, 8)

    def visit_STORE2(self, node):
        self.do_store(node, 16)

    def visit_STORE4(self, node):
        self.do_store(node, 32)

    def visit_ADD(self, node):
        dest = self.visit(node.left)
        src = self.visit(node.right)
        self.asm.add(self.reg_num(dest), self.reg_num(src))
        src.free()
        return dest

    def visit_SUB(self, node):
        dest = self.visit(node.left)
        src = self.visit(node.right)
        self.asm.sub(self.reg_num(dest), self.reg_num(src))
        src.free()
        return dest

    def do_shift(self, node, shift_func):
        dest = self.visit(node.left)
        shift = self.visit(node.right)

        self.asm.mov(EAX, self.reg_num(dest)) # switch to EAX because we might be trying to shift ECX
        self.asm.push(ECX)
        self.asm.mov(ECX, self.reg_num(shift))
        shift_func(EAX)
        self.asm.pop(ECX)
        self.asm.mov(self.reg_num(dest), EAX)

        shift.free()
        return dest

    def visit_LSH(self, node):
        return self.do_shift(node, self.asm.shl_cl)

    def visit_RSHI(self, node):
        return self.do_shift(node, self.asm.sar_cl)

    def visit_RSHU(self, node):
        return self.do_shift(node, self.asm.shr_cl)

    def visit_MULI(self, node):
        dest = self.visit(node.left)
        src = self.visit(node.right)
        print('skipping MULI')
        self.asm.nop()
        src.free()
        return dest

    def visit_DIVI(self, node):
        dest = self.visit(node.left)
        src = self.visit(node.right)
        print('skipping DIVI')
        self.asm.nop()
        src.free()
        return dest

    def visit_MODI(self, node):
        dest = self.visit(node.left)
        src = self.visit(node.right)
        print('skipping MODI')
        self.asm.nop()
        src.free()
        return dest

    def visit_NEGI(self, node):
        reg = self.visit(node.child)
        self.asm.neg(self.reg_num(reg))
        return reg

    def visit_BAND(self, node):
        dest = self.visit(node.left)
        src = self.visit(node.right)
        self.asm.band(self.reg_num(dest), self.reg_num(src))
        src.free()
        return dest

    def visit_BOR(self, node):
        dest = self.visit(node.left)
        src = self.visit(node.right)
        self.asm.bor(self.reg_num(dest), self.reg_num(src))
        src.free()
        return dest

    def visit_BXOR(self, node):
        dest = self.visit(node.left)
        src = self.visit(node.right)
        self.asm.bxor(self.reg_num(dest), self.reg_num(src))
        src.free()
        return dest

    def visit_BCOM(self, node):
        reg = self.visit(node.child)
        self.asm.bnot(self.reg_num(reg))
        return reg

    def visit_SEX8(self, node):
        reg = self.visit(node.child)
        self.asm.sext(self.reg_num(reg), 8)
        return reg

    def visit_SEX16(self, node):
        reg = self.visit(node.child)
        self.asm.sext(self.reg_num(reg), 16)
        return reg

    def visit_ARG(self, node):
        self.arg_size = max(self.arg_size, node.value - 4)
        reg = self.visit(node.child)
        self.asm.arg(node.value - 8, self.reg_num(reg))
        reg.free()

    def instruction_number_to_address(self, reg):
        self.asm.shl(self.reg_num(reg), 2)
        self.asm.load_label(EAX, self.instruction_addresses_label)
        self.asm.add(self.reg_num(reg), EAX)
        self.asm.load(self.reg_num(reg), self.reg_num(reg))

    def visit_CALL(self, node):
        if node.child.opcode == CONST:
            target = node.child.value
            if target not in self.sub_labels:
                self.sub_labels[target] = self.asm.label()
            label = self.sub_labels[target]
            self.asm.call(label)
            reg = self.regs.new()
        else:
            reg = self.visit(node.child)
            self.instruction_number_to_address(reg)
            self.asm.call_reg(self.reg_num(reg))
        self.asm.mov(self.reg_num(reg), EAX)
        return reg

    def visit_JUMP(self, node):
        if node.child.opcode == CONST:
            # if it's a jump to const, successors[1] should be the target
            self.asm.jmp(self.successor_labels[1])
        else:
            reg = self.visit(node.child)
            self.instruction_number_to_address(reg)
            self.asm.jmp_reg(self.reg_num(reg))
            reg.free()

    def do_conditional_jump(self, node, cond):
        left = self.visit(node.left)
        right = self.visit(node.right)
        self.asm.cmp(self.reg_num(left), self.reg_num(right))
        if self.invert_conditions:
            self.asm.jmp_cond(cond_inverses[cond], self.successor_labels[0])
            self.asm.jmp(self.successor_labels[1])
        else:
            self.asm.jmp_cond(cond, self.successor_labels[1])
            self.asm.jmp(self.successor_labels[0])
        left.free()
        right.free()

    def visit_EQ(self, node):
        self.do_conditional_jump(node, COND_EQ)

    def visit_NE(self, node):
        self.do_conditional_jump(node, COND_NE)

    def visit_LTI(self, node):
        self.do_conditional_jump(node, COND_LTI)

    def visit_LEI(self, node):
        self.do_conditional_jump(node, COND_LEI)

    def visit_GTI(self, node):
        self.do_conditional_jump(node, COND_GTI)

    def visit_GEI(self, node):
        self.do_conditional_jump(node, COND_GEI)

    def visit_LTU(self, node):
        self.do_conditional_jump(node, COND_LTU)

    def visit_LEU(self, node):
        self.do_conditional_jump(node, COND_LEU)

    def visit_GTU(self, node):
        self.do_conditional_jump(node, COND_GTU)

    def visit_GEU(self, node):
        self.do_conditional_jump(node, COND_GEU)

    # TODO: check these
    # EQ and NE need to check for parity flag too?
    # are the rest ok?
    def do_conditional_jump_float(self, node, cond):
        left = self.visit(node.left)
        right = self.visit(node.right)
        self.asm.movd(XMM0, self.reg_num(left))
        self.asm.movd(XMM1, self.reg_num(right))
        self.asm.ucomiss(XMM0, XMM1)
        if self.invert_conditions:
            self.asm.jmp_cond(cond_inverses[cond], self.successor_labels[0])
            self.asm.jmp(self.successor_labels[1])
        else:
            self.asm.jmp_cond(cond, self.successor_labels[1])
            self.asm.jmp(self.successor_labels[0])
        left.free()
        right.free()

    def visit_EQF(self, node):
        self.do_conditional_jump_float(node, COND_EQ)

    def visit_NEF(self, node):
        self.do_conditional_jump_float(node, COND_NE)

    def visit_LTF(self, node):
        self.do_conditional_jump_float(node, COND_LTU)

    def visit_LEF(self, node):
        self.do_conditional_jump_float(node, COND_LEU)

    def visit_GTF(self, node):
        self.do_conditional_jump_float(node, COND_GTU)

    def visit_GEF(self, node):
        self.do_conditional_jump_float(node, COND_GEU)

    def visit_ADDF(self, node):
        dest = self.visit(node.left)
        src = self.visit(node.right)
        self.asm.movd(XMM0, self.reg_num(dest))
        self.asm.movd(XMM1, self.reg_num(src))
        self.asm.addss(XMM0, XMM1)
        self.asm.movd(self.reg_num(dest), XMM0)
        src.free()
        return dest

    def visit_SUBF(self, node):
        dest = self.visit(node.left)
        src = self.visit(node.right)
        self.asm.movd(XMM0, self.reg_num(dest))
        self.asm.movd(XMM1, self.reg_num(src))
        self.asm.subss(XMM0, XMM1)
        self.asm.movd(self.reg_num(dest), XMM0)
        src.free()
        return dest

    def visit_MULF(self, node):
        dest = self.visit(node.left)
        src = self.visit(node.right)
        self.asm.movd(XMM0, self.reg_num(dest))
        self.asm.movd(XMM1, self.reg_num(src))
        self.asm.mulss(XMM0, XMM1)
        self.asm.movd(self.reg_num(dest), XMM0)
        src.free()
        return dest

    def visit_DIVF(self, node):
        dest = self.visit(node.left)
        src = self.visit(node.right)
        self.asm.movd(XMM0, self.reg_num(dest))
        self.asm.movd(XMM1, self.reg_num(src))
        self.asm.divss(XMM0, XMM1)
        self.asm.movd(self.reg_num(dest), XMM0)
        src.free()
        return dest

    def visit_NEGF(self, node):
        reg = self.visit(node.child)
        self.asm.load_const(EAX, 0x80000000)
        self.asm.bxor(self.reg_num(reg), EAX)
        return reg

    def visit_CVIF(self, node):
        reg = self.visit(node.child)
        self.asm.cvtsi2ss(XMM0, self.reg_num(reg))
        self.asm.movd(self.reg_num(reg), XMM0)
        return reg

    def visit_CVFI(self, node):
        reg = self.visit(node.child)
        self.asm.movd(XMM0, self.reg_num(reg))
        self.asm.cvtss2si(self.reg_num(reg), XMM0)
        return reg

    def visit_BLOCK_COPY(self, node):
        dest = self.visit(node.left)
        src = self.visit(node.right)
        size = node.value

        self.asm.push(EDI)
        self.asm.push(ESI)
        self.asm.push(ECX)

        self.asm.mov(EDI, self.reg_num(dest))
        self.asm.mov(ESI, self.reg_num(src))
        self.asm.load_const(ECX, size)
        self.asm.rep_stosb()

        self.asm.pop(ECX)
        self.asm.pop(ESI)
        self.asm.pop(EDI)

        dest.free()
        src.free()

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
        cg.generate(sub)
    cg.finish()

    for addr, label in cg.sub_labels.items():
        if label.address is None:
            print(f'unbound label at {addr:08x}')

    with open('C:/Users/Josh/Desktop/bla', 'wb') as f:
        f.write(cg.asm.code)

    qvm_map = []

    with open('qagame.map', 'rb') as f:
        for line in f:
            type, address, name = line.split()
            if int(type) == 0:
                qvm_map.append((int(address, 16), name.decode()))

    with open('C:/Users/Josh/Desktop/bla_symbols', 'wb') as f:
        for address, name in qvm_map:
            if address in cg.sub_labels:
                label = cg.sub_labels[address]
                assert label.address is not None
                f.write(f'{name} {label.address:#x}\n'.encode())

if __name__ == '__main__':
    main()
