import argparse
import binascii
import struct
import sys
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
    def __init__(self, use_sse=True):
        self.asm = Assembler(base=0x10000000)
        self.sub_labels = {} # for CONST calls

        # for indirect jumps and calls
        self.instruction_addresses = []
        self.instruction_addresses_label = self.asm.label()

        self.use_sse = use_sse

    def generate(self, sub):
        # reset register use for every sub
        self.regs = RegAllocator(self.spill, self.unspill, [EBX, ECX, EDX, ESI, EDI])
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
                self.asm.mov(EAX, offset)
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

    def spill_offset(self, reg):
        return self.frame_size + 4 + reg.offset * 4

    def spill(self, reg):
        if reg.offset >= self.num_spills:
            self.num_spills = reg.offset + 1

        self.asm.mov([EBP - self.spill_offset(reg)], reg.get())

    def unspill(self, reg):
        self.asm.mov(reg.get(), [EBP - self.spill_offset(reg)])

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
        self.asm.sub(ESP, node.value)

    def visit_LEAVE(self, node):
        assert len(node.children) <= 1
        if len(node.children) == 1:
            reg = self.visit(node.child)
            self.asm.mov(EAX, reg.get())
            reg.free()
        self.asm.mov(ESP, EBP)
        self.asm.pop(EBP)
        self.asm.ret()

    def visit_PUSH(self, node):
        reg = self.regs.new()
        self.asm.mov(reg.get(), 0)
        return reg

    def visit_CONST(self, node):
        reg = self.regs.new()
        self.asm.mov(reg.get(), node.value)
        return reg

    def visit_LOCAL(self, node):
        reg = self.regs.new()
        self.asm.lea(reg.get(), [EBP + (node.value - self.frame_size)])
        return reg

    def do_load(self, node, size):
        reg = self.visit(node.child)

        if size == 32:
            self.asm.mov(reg.get(), [reg.get()])
        elif size == 16:
            self.asm.mov(AX, [reg.get()])
            self.asm.movzx(reg.get(), AX)
        elif size == 8:
            self.asm.mov(AL, [reg.get()])
            self.asm.movzx(reg.get(), AL)

        return reg

    def visit_LOAD1(self, node):
        return self.do_load(node, 8)

    def visit_LOAD2(self, node):
        return self.do_load(node, 16)

    def visit_LOAD4(self, node):
        return self.do_load(node, 32)

    def do_store(self, node, size):
        src = self.visit(node.right)
        dest = self.visit(node.left)

        if size == 32:
            self.asm.mov([dest.get()], src.get())
        elif size == 16:
            self.asm.mov(EAX, src.get())
            self.asm.mov([dest.get()], AX)
        elif size == 8:
            self.asm.mov(EAX, src.get())
            self.asm.mov([dest.get()], AL)

        src.free()
        dest.free()

    def visit_STORE1(self, node):
        self.do_store(node, 8)

    def visit_STORE2(self, node):
        self.do_store(node, 16)

    def visit_STORE4(self, node):
        self.do_store(node, 32)

    def visit_ADD(self, node):
        dest = self.visit(node.left)
        src = self.visit(node.right)
        self.asm.add(dest.get(), src.get())
        src.free()
        return dest

    def visit_SUB(self, node):
        dest = self.visit(node.left)
        src = self.visit(node.right)
        self.asm.sub(dest.get(), src.get())
        src.free()
        return dest

    def do_shift(self, node, shift_func):
        dest = self.visit(node.left)
        shift = self.visit(node.right)

        self.asm.mov(EAX, dest.get()) # switch to EAX because we might be trying to shift ECX
        self.asm.push(ECX)
        self.asm.mov(ECX, shift.get())
        shift_func(EAX, CL)
        self.asm.pop(ECX)
        self.asm.mov(dest.get(), EAX)

        shift.free()
        return dest

    def visit_LSH(self, node):
        return self.do_shift(node, self.asm.shl)

    def visit_RSHI(self, node):
        return self.do_shift(node, self.asm.sar)

    def visit_RSHU(self, node):
        return self.do_shift(node, self.asm.shr)

    def visit_MULI(self, node):
        dest = self.visit(node.left)
        src = self.visit(node.right)
        self.asm.imul(dest.get(), src.get())
        src.free()
        return dest

    def do_divmod(self, node, mod=False):
        dest = self.visit(node.left)
        src = self.visit(node.right)

        # make sure registers are loaded ahead of time so spilling doesn't interfere with anything
        dest_reg = dest.get()
        src_reg = src.get()

        # EDX is used by idiv
        # EBX is used for src in case it was EDX
        self.asm.push(EBX)
        self.asm.push(EDX)

        self.asm.mov(EAX, dest_reg)
        self.asm.mov(EBX, src_reg)
        self.asm.cdq()
        self.asm.idiv(EBX)
        if mod:
            self.asm.mov(EAX, EDX)

        self.asm.pop(EDX)
        self.asm.pop(EBX)

        self.asm.mov(dest_reg, EAX)
        src.free()
        return dest

    def visit_DIVI(self, node):
        return self.do_divmod(node)

    def visit_MODI(self, node):
        return self.do_divmod(node, mod=True)

    def visit_NEGI(self, node):
        reg = self.visit(node.child)
        self.asm.neg(reg.get())
        return reg

    def visit_BAND(self, node):
        dest = self.visit(node.left)
        src = self.visit(node.right)
        self.asm.band(dest.get(), src.get())
        src.free()
        return dest

    def visit_BOR(self, node):
        dest = self.visit(node.left)
        src = self.visit(node.right)
        self.asm.bor(dest.get(), src.get())
        src.free()
        return dest

    def visit_BXOR(self, node):
        dest = self.visit(node.left)
        src = self.visit(node.right)
        self.asm.bxor(dest.get(), src.get())
        src.free()
        return dest

    def visit_BCOM(self, node):
        reg = self.visit(node.child)
        self.asm.bnot(reg.get())
        return reg

    def visit_SEX8(self, node):
        reg = self.visit(node.child)
        self.asm.mov(EAX, reg.get())
        self.asm.movsx(reg.get(), AL)
        return reg

    def visit_SEX16(self, node):
        reg = self.visit(node.child)
        self.asm.mov(EAX, reg.get())
        self.asm.movsx(reg.get(), AX)
        return reg

    def visit_ARG(self, node):
        self.arg_size = max(self.arg_size, node.value - 4)
        reg = self.visit(node.child)
        self.asm.mov([ESP + (node.value - 8)], reg.get())
        reg.free()

    def instruction_number_to_address(self, reg):
        self.asm.shl(reg.get(), 2)
        self.asm.mov(EAX, self.instruction_addresses_label)
        self.asm.add(reg.get(), EAX)
        self.asm.mov(reg.get(), [reg.get()])

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
            self.asm.call(reg.get())
        self.asm.mov(reg.get(), EAX)
        return reg

    def visit_JUMP(self, node):
        if node.child.opcode == CONST:
            # if it's a jump to const, successors[1] should be the target
            self.asm.jmp(self.successor_labels[1])
        else:
            reg = self.visit(node.child)
            self.instruction_number_to_address(reg)
            self.asm.jmp(reg.get())
            reg.free()

    def do_conditional_jump(self, node, jump_func):
        left = self.visit(node.left)
        right = self.visit(node.right)
        self.asm.cmp(left.get(), right.get())
        jump_func(self.successor_labels[1])
        self.asm.jmp(self.successor_labels[0])
        left.free()
        right.free()

    def visit_EQ(self, node):
        self.do_conditional_jump(node, self.asm.je)

    def visit_NE(self, node):
        self.do_conditional_jump(node, self.asm.jne)

    def visit_LTI(self, node):
        self.do_conditional_jump(node, self.asm.jl)

    def visit_LEI(self, node):
        self.do_conditional_jump(node, self.asm.jle)

    def visit_GTI(self, node):
        self.do_conditional_jump(node, self.asm.jg)

    def visit_GEI(self, node):
        self.do_conditional_jump(node, self.asm.jge)

    def visit_LTU(self, node):
        self.do_conditional_jump(node, self.asm.jb)

    def visit_LEU(self, node):
        self.do_conditional_jump(node, self.asm.jbe)

    def visit_GTU(self, node):
        self.do_conditional_jump(node, self.asm.ja)

    def visit_GEU(self, node):
        self.do_conditional_jump(node, self.asm.jae)

    # TODO: check these
    # EQ and NE need to check for parity flag too?
    # are the rest ok?
    def do_conditional_jump_float(self, node, jump_func):
        left = self.visit(node.left)
        right = self.visit(node.right)
        if self.use_sse:
            self.asm.movd(XMM0, left.get())
            self.asm.movd(XMM1, right.get())
            self.asm.ucomiss(XMM0, XMM1)
        else:
            self.asm.push(right.get())
            self.asm.fld([ESP])
            self.asm.mov([ESP], left.get())
            self.asm.fld([ESP])
            self.asm.fcomip(1)
            self.asm.fstp(0)
            self.asm.pop(left.get()) # add esp, 4 would change flags. should we even push in the first place?
        jump_func(self.successor_labels[1])
        self.asm.jmp(self.successor_labels[0])
        left.free()
        right.free()

    def visit_EQF(self, node):
        self.do_conditional_jump_float(node, self.asm.je)

    def visit_NEF(self, node):
        self.do_conditional_jump_float(node, self.asm.jne)

    def visit_LTF(self, node):
        self.do_conditional_jump_float(node, self.asm.jb)

    def visit_LEF(self, node):
        self.do_conditional_jump_float(node, self.asm.jbe)

    def visit_GTF(self, node):
        self.do_conditional_jump_float(node, self.asm.ja)

    def visit_GEF(self, node):
        self.do_conditional_jump_float(node, self.asm.jae)

    def do_sse_bin_op(self, node, op_func):
        dest = self.visit(node.left)
        src = self.visit(node.right)
        self.asm.movd(XMM0, dest.get())
        self.asm.movd(XMM1, src.get())
        op_func(XMM0, XMM1)
        self.asm.movd(dest.get(), XMM0)
        src.free()
        return dest

    def do_x87_bin_op(self, node, op_func):
        dest = self.visit(node.left)
        src = self.visit(node.right)
        self.asm.push(dest.get())
        self.asm.fld([ESP])
        self.asm.mov([ESP], src.get())
        self.asm.fld([ESP])
        op_func()
        self.asm.fstp([ESP])
        self.asm.pop(dest.get())
        src.free()
        return dest

    def visit_ADDF(self, node):
        if self.use_sse:
            return self.do_sse_bin_op(node, self.asm.addss)
        else:
            return self.do_x87_bin_op(node, self.asm.faddp)

    def visit_SUBF(self, node):
        if self.use_sse:
            return self.do_sse_bin_op(node, self.asm.subss)
        else:
            return self.do_x87_bin_op(node, self.asm.fsubp)

    def visit_MULF(self, node):
        if self.use_sse:
            return self.do_sse_bin_op(node, self.asm.mulss)
        else:
            return self.do_x87_bin_op(node, self.asm.fmulp)

    def visit_DIVF(self, node):
        if self.use_sse:
            return self.do_sse_bin_op(node, self.asm.divss)
        else:
            return self.do_x87_bin_op(node, self.asm.fdivp)

    def visit_NEGF(self, node):
        reg = self.visit(node.child)
        self.asm.mov(EAX, 0x80000000)
        self.asm.bxor(reg.get(), EAX)
        return reg

    def visit_CVIF(self, node):
        reg = self.visit(node.child)
        if self.use_sse:
            self.asm.cvtsi2ss(XMM0, reg.get())
            self.asm.movd(reg.get(), XMM0)
        else:
            self.asm.push(reg.get())
            self.asm.fild([ESP])
            self.asm.fstp([ESP])
            self.asm.pop(reg.get())
        return reg

    def visit_CVFI(self, node):
        reg = self.visit(node.child)
        if self.use_sse:
            self.asm.movd(XMM0, reg.get())
            self.asm.cvttss2si(reg.get(), XMM0)
        else:
            self.asm.push(reg.get())
            self.asm.fld([ESP])
            self.asm.fistp([ESP])
            self.asm.pop(reg.get())
        return reg

    def visit_BLOCK_COPY(self, node):
        dest = self.visit(node.left)
        src = self.visit(node.right)
        size = node.value

        self.asm.push(EDI)
        self.asm.push(ESI)
        self.asm.push(ECX)

        self.asm.mov(EDI, dest.get())
        self.asm.mov(ESI, src.get())
        self.asm.mov(ECX, size)
        self.asm.rep_movsb()

        self.asm.pop(ECX)
        self.asm.pop(ESI)
        self.asm.pop(EDI)

        dest.free()
        src.free()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input', help='the qvm to translate')
    parser.add_argument('output', help='the resulting x86 code')
    parser.add_argument('--map', help='a q3asm map file')
    parser.add_argument('--symbols', help='dump symbols to SYMBOLS')
    parser.add_argument('--data', help='dump the data section to DATA') # TODO
    parser.add_argument('--lit',  help='dump the lit section to LIT') # TODO
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
        cg.generate(sub)
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
