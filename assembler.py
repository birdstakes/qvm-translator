import binascii
import struct

EAX = 0
ECX = 1
EDX = 2
EBX = 3
ESP = 4
EBP = 5
ESI = 6
EDI = 7

COND_EQ  = 0
COND_NE  = 1
COND_LTI = 2
COND_LEI = 3
COND_GTI = 4
COND_GEI = 5
COND_LTU = 6
COND_LEU = 7
COND_GTU = 8
COND_GEU = 9

class LabelUse:
    def __init__(self, address, relative_to=0):
        self.address = address
        self.relative_to = relative_to

class Label:
    def __init__(self, asm):
        self.asm = asm
        self.address = None
        self.uses = []

    def bind(self):
        self.address = self.asm.current_address()

class Assembler:
    def __init__(self, base=0):
        self.code = bytearray()
        self.labels = []
        self.base = base

    def current_address(self):
        return len(self.code) + self.base

    def label(self):
        label = Label(self)
        self.labels.append(label)
        return label

    def fixup_labels(self):
        dummy_address = self.current_address()
        self.bp()

        for label in self.labels:
            if label.address is None:
                print('warning: unbound label')
                label.address = dummy_address
            for use in label.uses:
                struct.pack_into('<I', self.code, use.address - self.base, (label.address - use.relative_to) & 0xffffffff)

    def emit(self, data):
        self.code.extend(data)

    def emit32(self, value):
        self.emit(struct.pack('<I', value & 0xffffffff))

    def align(self, n):
        while len(self.code) % n != 0:
            self.emit([0])

    def nop(self):
        self.emit([0x90])

    def bp(self):
        self.emit([0xcc])
    
    def arg(self, offset, reg):
        modrm = 0b10000000 | ((reg & 7) << 3) | (0b100)
        sib = 0b00100000 | ESP
        self.emit([0x89, modrm, sib])
        self.emit32(offset)

    def call(self, label):
        self.emit([0xe8])
        label.uses.append(LabelUse(self.current_address(), relative_to=self.current_address() + 4))
        self.emit32(0)

    def call_reg(self, reg):
        modrm = 0b11000000 | (2 << 3) | (reg & 7)
        self.emit([0xff, modrm])

    def ret(self):
        self.emit([0xc3])

    def jmp(self, label):
        self.emit([0xe9])
        label.uses.append(LabelUse(self.current_address(), relative_to=self.current_address() + 4))
        self.emit32(0)

    def jmp_reg(self, reg):
        modrm = 0b11000000 | (4 << 3) | (reg & 7)
        self.emit([0xff, modrm])

    def cmp(self, reg1, reg2):
        modrm = 0b11000000 | ((reg2 & 7) << 3) | (reg1 & 7)
        self.emit([0x39, modrm])

    def jmp_cond(self, cond, label):
        self.emit({
            COND_EQ:  [0x0f, 0x84],
            COND_NE:  [0x0f, 0x85],
            COND_LTI: [0x0f, 0x8c],
            COND_LEI: [0x0f, 0x8e],
            COND_GTI: [0x0f, 0x8f],
            COND_GEI: [0x0f, 0x8d],
            COND_LTU: [0x0f, 0x82],
            COND_LEU: [0x0f, 0x86],
            COND_GTU: [0x0f, 0x87],
            COND_GEU: [0x0f, 0x83],
        }[cond])
        label.uses.append(LabelUse(self.current_address(), relative_to=self.current_address() + 4))
        self.emit32(0)

    def mov(self, dest_reg, src_reg):
        modrm = 0b11000000 | ((src_reg & 7) << 3) | (dest_reg & 7)
        self.emit([0x89, modrm])

    def load_const(self, reg, value):
        self.emit([0xb8 + reg])
        self.emit32(value)

    def load_label(self, reg, label):
        self.emit([0xb8 + reg])
        label.uses.append(LabelUse(self.current_address()))
        self.emit32(0)

    def load(self, dest_reg, src_reg, size=32):
        # TODO zero/sign extend
        modrm = ((dest_reg & 7) << 3) | (src_reg & 7)
        if size == 32:
            self.emit([0x8b, modrm])
        elif size == 16:
            self.emit([0x66, 0x8b, modrm])
        elif size == 8:
            self.emit([0x8a, modrm])
        else:
            raise Exception('invalid memory reference size')

    def store(self, dest_reg, src_reg, size=32):
        modrm = ((src_reg & 7) << 3) | (dest_reg & 7)
        if size == 32:
            self.emit([0x89, modrm])
        elif size == 16:
            self.emit([0x66, 0x89, modrm])
        elif size == 8:
            self.emit([0x88, modrm])
        else:
            raise Exception('invalid memory reference size')

    def local(self, dest_reg, offset):
        modrm = 0b10000000 | ((dest_reg & 7) << 3) | EBP
        self.emit([0x8d, modrm])
        self.emit32(offset)

    def add(self, dest_reg, src_reg):
        modrm = 0b11000000 | ((dest_reg & 7) << 3) | (src_reg & 7)
        self.emit([0x03, modrm])

    def sub(self, dest_reg, src_reg):
        modrm = 0b11000000 | ((src_reg & 7) << 3) | (dest_reg & 7)
        self.emit([0x29, modrm])

    def sub_imm(self, dest_reg, value):
        modrm = 0b11000000 | (5 << 3) | (dest_reg & 7)
        self.emit([0x81, modrm])
        self.emit32(value)

    def shl(self, dest_reg, shift):
        modrm = 0b11000000 | (4 << 3) | (dest_reg & 7)
        self.emit([0xc1, modrm, shift])

    def shl_cl(self, dest_reg):
        modrm = 0b11000000 | (4 << 3) | (dest_reg & 7)
        self.emit([0xd3, modrm])

    def sext(self, reg, size):
        modrm = 0b11000000 | ((reg & 7) << 3) | (reg & 7)
        if size == 8:
            self.emit([0x0f, 0xbe, modrm])
        elif size == 16:
            self.emit([0x0f, 0xbf, modrm])
        else:
            raise Exception('invalid sign extention size')

    def push(self, reg):
        self.emit([0x50 + reg])

    def pop(self, reg):
        self.emit([0x58 + reg])

def main():
    asm = Assembler()

    l1 = asm.label()
    l2 = asm.label()

    asm.jmp(l1)
    asm.nop()
    asm.nop()
    l1.bind()
    asm.nop()
    asm.load_const(EBP, 123)
    asm.mov(EAX, EBX)
    asm.store(EBX, ECX)
    asm.load_label(EAX, l2)
    asm.load(EAX, EAX, size=8)
    asm.load(EAX, EAX, size=16)
    asm.load(EAX, EAX, size=32)
    asm.store(EAX, EAX, size=8)
    asm.store(EAX, EAX, size=16)
    asm.store(EAX, EAX, size=32)
    asm.add(EBX, EDX)
    l2.bind()
    asm.emit32(0x12345678)

    asm.fixup_labels()

    print(asm.labels[0].address)
    print(binascii.hexlify(asm.code))

if __name__ == '__main__':
    main()
