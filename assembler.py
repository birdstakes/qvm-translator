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
    def __init__(self):
        self.code = bytearray()
        self.labels = []

    def current_address(self):
        return len(self.code)

    def label(self):
        label = Label(self)
        self.labels.append(label)
        return label

    def fixup_labels(self):
        for label in self.labels:
            for use in label.uses:
                struct.pack_into('<I', self.code, use.address, label.address - use.relative_to)

    def emit(self, data):
        self.code.extend(data)

    def emit32(self, value):
        self.emit(struct.pack('<I', value & 0xffffffff))

    def nop(self):
        self.emit([0x90])

    def bp(self):
        self.emit([0xcc])
    
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
        modrm = 0b11000000 | ((dest_reg & 7) << 3) | (src_reg & 7)
        self.emit([0x29, modrm])

    def subimm(self, dest_reg, value):
        modrm = 0b11000000 | (5 << 3) | (dest_reg & 7)
        self.emit([0x81, modrm])
        self.emit32(value)

    def shl_cl(self, dest_reg):
        modrm = 0b11000000 | (4 << 3) | (dest_reg & 7)
        self.emit([0xd3, modrm])

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
