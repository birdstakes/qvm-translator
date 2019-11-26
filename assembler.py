import copy
import struct
import sys

def modrm(mod, rm, reg):
    assert 0 <= mod <= 0b11
    assert 0 <= rm <= 0b111
    assert 0 <= reg <= 0b111
    return (mod << 6) | (reg << 3) | rm

def sib(scale, index, base):
    scale = [1, 2, 4, 8].index(scale)
    return (scale << 6) | (index<< 3) | base

class Rm32:
    def modrm_bytes(self, reg):
        raise NotImplementedError

class R8:
    def __init__(self, name, num):
        self.name = name
        self.num = num

class R16:
    def __init__(self, name, num):
        self.name = name
        self.num = num

class XMM:
    def __init__(self, name, num):
        self.name = name
        self.num = num

class R32(Rm32):
    def __init__(self, name, num):
        self.name = name
        self.num = num

    def modrm_bytes(self, reg):
        return bytearray([modrm(0b11, self.num, reg)])

    def __add__(self, other):
        return EffectiveAddress(base=self) + other

    def __radd__(self, other):
        return self + other

    def __sub__(self, other):
        return EffectiveAddress(base=self) + -other

    def __mul__(self, other):
        return EffectiveAddress(index=self, scale=other)

class EffectiveAddress(Rm32):
    def __init__(self, base=None, index=None, scale=None, disp=None):
        self.base = base
        self.index = index
        self.scale = scale
        self.disp = disp

    @staticmethod
    def from_list(l):
        assert len(l) == 1
        if isinstance(l[0], EffectiveAddress):
            return l[0]

        elif isinstance(l[0], R32):
            return EffectiveAddress(base=l[0])

        elif isinstance(l[0], int):
            return EffectiveAddress(disp=l[0])

        else:
            raise Exception('invalid memory reference')

    def only_base(self):
        if self.base is None:
            return False
        if self.scale is not None:
            return False
        if self.index is not None:
            return False
        if self.disp is not None:
            return False
        return True

    def only_disp(self):
        if self.base is not None:
            return False
        if self.scale is not None:
            return False
        if self.index is not None:
            return False
        if self.disp is None:
            return False
        return True

    def only_base_disp(self):
        if self.base is None:
            return False
        if self.scale is not None:
            return False
        if self.index is not None:
            return False
        if self.disp is None:
            return False
        return True

    def modrm_bytes(self, reg):
        res = bytearray()

        # there is no [reg] addressing mode for ebp, so add 0 displacement
        if self.base == EBP and self.disp is None:
            self.disp = 0

        scale = self.scale
        if scale is None:
            scale = 1

        if self.index is not None:
            if self.index == ESP:
                raise Exception('invalid index')
            index = self.index.num
        else:
            index = 0b100

        if self.disp is not None:
            small_disp = not self.only_disp() and -128 <= self.disp <= 127

        #
        # [base]
        #
        # fall through to general case for ESP because rm=0b100 means [SIB] instead of [reg]
        # fall through to general case for EBP because rm=0b101 means [disp32]
        if self.only_base() and self.base not in (EBP, ESP):
            res.append(modrm(mod=0b00, rm=self.base.num, reg=reg))
            return res

        #
        # [base + disp]
        #
        # fall through to general case for ESP because rm=0b100 means [SIB + disp] instead of [reg + disp]
        elif self.only_base_disp() and self.base != ESP:
            if small_disp:
                res.append(modrm(mod=0b01, rm=self.base.num, reg=reg))
            else:
                res.append(modrm(mod=0b10, rm=self.base.num, reg=reg))

        #
        # [disp]
        #
        elif self.only_disp():
            res.append(modrm(mod=0b00, rm=0b101, reg=reg))

        #
        # [base + index*scale]
        # [base + index*scale + disp]
        #
        else:
            if self.disp is None:
                mod = 0b00
            elif small_disp:
                mod = 0b01
            else:
                mod = 0b10

            res.append(modrm(mod, 0b100, reg))
            res.append(sib(scale, index, self.base.num))

        if self.disp is not None:
            if small_disp:
                res.extend(struct.pack('<B', self.disp & 0xff))
            else:
                res.extend(struct.pack('<I', self.disp & 0xffffffff))

        return res

    def __add__(self, other):
        res = copy.copy(self)

        if isinstance(other, int):
            assert res.disp is None
            res.disp = other
            return res

        if isinstance(other, R32):
            assert res.base is None
            res.base = other
            return res

        if isinstance(other, EffectiveAddress):
            if other.base:
                # TODO: could add other*1 as index and scale if we already have a base
                # right now [EBX + EBX] won't work, but [EBX + EBX*1] will
                assert res.base is None
                res.base = other.base

            if other.index and other.scale:
                assert res.index is None and res.scale is None
                res.index = other.index
                res.scale = other.scale

            if other.disp is not None:
                assert res.disp is None
                res.disp = other.disp

            return res

        print(self, other)
        raise Exception('oops')

AL = R8('al', 0)
CL = R8('cl', 1)
DL = R8('dl', 2)
BL = R8('bl', 3)
AH = R8('ah', 4)
CH = R8('ch', 5)
DH = R8('dh', 6)
BH = R8('bh', 7)

AX = R16('ax', 0)
CX = R16('cx', 1)
DX = R16('dx', 2)
BX = R16('bx', 3)
SP = R16('sp', 4)
BP = R16('bp', 5)
SI = R16('si', 6)
DI = R16('di', 7)

EAX = R32('eax', 0)
ECX = R32('ecx', 1)
EDX = R32('edx', 2)
EBX = R32('ebx', 3)
ESP = R32('esp', 4)
EBP = R32('ebp', 5)
ESI = R32('esi', 6)
EDI = R32('edi', 7)

XMM0 = XMM('xmm0', 0)
XMM1 = XMM('xmm1', 1)
XMM2 = XMM('xmm2', 2)
XMM3 = XMM('xmm3', 3)
XMM4 = XMM('xmm4', 4)
XMM5 = XMM('xmm5', 5)
XMM6 = XMM('xmm6', 6)
XMM7 = XMM('xmm7', 7)

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

def accept_lists_as_addresses(f):
    def wrap(*args):
        args = [EffectiveAddress.from_list(arg) if isinstance(arg, list) else arg for arg in args]
        f(*args)
    return wrap

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
        for label in self.labels:
            if label.address is None:
                sys.stderr.write('warning: unbound label')
                continue
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

    def int3(self):
        self.emit([0xcc])

    @accept_lists_as_addresses
    def call(self, target):
        if isinstance(target, Label):
            self.emit([0xe8])
            target.uses.append(LabelUse(self.current_address(), relative_to=self.current_address() + 4))
            self.emit32(0)

        elif isinstance(target, Rm32):
            self.emit([0xff])
            self.emit(target.modrm_bytes(reg=2))

        else:
            raise Exception('unsupported operands to call')

    def ret(self):
        self.emit([0xc3])

    @accept_lists_as_addresses
    def jmp(self, target):
        if isinstance(target, Label):
            self.emit([0xe9])
            target.uses.append(LabelUse(self.current_address(), relative_to=self.current_address() + 4))
            self.emit32(0)

        elif isinstance(target, Rm32):
            self.emit([0xff])
            self.emit(target.modrm_bytes(reg=4))

        else:
            raise Exception('unsupported operands to jmp')

    def jcc(self, opcode, label):
        self.emit(opcode)
        label.uses.append(LabelUse(self.current_address(), relative_to=self.current_address() + 4))
        self.emit32(0)

    def je(self, label):
        self.jcc([0x0f, 0x84], label)

    def jne(self, label):
        self.jcc([0x0f, 0x85], label)

    def jl(self, label):
        self.jcc([0x0f, 0x8c], label)

    def jle(self, label):
        self.jcc([0x0f, 0x8e], label)

    def jg(self, label):
        self.jcc([0x0f, 0x8f], label)

    def jge(self, label):
        self.jcc([0x0f, 0x8d], label)

    def jb(self, label):
        self.jcc([0x0f, 0x82], label)

    def jbe(self, label):
        self.jcc([0x0f, 0x86], label)

    def ja(self, label):
        self.jcc([0x0f, 0x87], label)

    def jae(self, label):
        self.jcc([0x0f, 0x83], label)

    @accept_lists_as_addresses
    def cmp(self, dest, src):
        if isinstance(dest, Rm32) and isinstance(src, R32):
            self.emit([0x39])
            self.emit(dest.modrm_bytes(reg=src.num))
        else:
            raise Exception(f'unsupported operands to cmp')

    @accept_lists_as_addresses
    def lea(self, dest, src):
        if isinstance(dest, R32) and isinstance(src, EffectiveAddress):
            self.emit([0x8d])
            self.emit(src.modrm_bytes(reg=dest.num))
        else:
            raise Exception('unsupported operands to lea')

    @accept_lists_as_addresses
    def mov(self, dest, src):
        if isinstance(dest, R32) and isinstance(src, int):
            self.emit([0xb8 + dest.num])
            self.emit32(src)

        elif isinstance(dest, R32) and isinstance(src, Label):
            self.emit([0xb8 + dest.num])
            src.uses.append(LabelUse(self.current_address()))
            self.emit32(0)

        elif isinstance(dest, Rm32) and isinstance(src, int):
            self.emit([0xc7])
            self.emit(dest.modrm_bytes(reg=0))
            self.emit32(src)

        elif isinstance(dest, Rm32) and isinstance(src, R32):
            self.emit([0x89])
            self.emit(dest.modrm_bytes(reg=src.num))

        elif isinstance(dest, R32) and isinstance(src, Rm32):
            self.emit([0x8b])
            self.emit(src.modrm_bytes(reg=dest.num))

        elif isinstance(dest, R8) and isinstance(src, EffectiveAddress):
            self.emit([0x8a])
            self.emit(src.modrm_bytes(reg=dest.num))

        elif isinstance(dest, EffectiveAddress) and isinstance(src, R8):
            self.emit([0x88])
            self.emit(dest.modrm_bytes(reg=src.num))

        elif isinstance(dest, R16) and isinstance(src, EffectiveAddress):
            self.emit([0x66, 0x8b])
            self.emit(src.modrm_bytes(reg=dest.num))

        elif isinstance(dest, EffectiveAddress) and isinstance(src, R16):
            self.emit([0x66, 0x89])
            self.emit(dest.modrm_bytes(reg=src.num))

        else:
            raise Exception('unsupported operands to mov')

    @accept_lists_as_addresses
    def add(self, dest, src):
        if isinstance(dest, Rm32) and isinstance(src, int):
            self.emit([0x81])
            self.emit(dest.modrm_bytes(reg=0))
            self.emit32(src)
        elif isinstance(dest, Rm32) and isinstance(src, R32):
            self.emit([0x01])
            self.emit(dest.modrm_bytes(reg=src.num))
        else:
            raise Exception(f'unsupported operands to add')

    # TODO use capital instruction names so we don't have to add a b in front of these?

    @accept_lists_as_addresses
    def band(self, dest, src):
        if isinstance(dest, Rm32) and isinstance(src, R32):
            self.emit([0x21])
            self.emit(dest.modrm_bytes(reg=src.num))
        else:
            raise Exception(f'unsupported operands to and')

    @accept_lists_as_addresses
    def bor(self, dest, src):
        if isinstance(dest, Rm32) and isinstance(src, R32):
            self.emit([0x09])
            self.emit(dest.modrm_bytes(reg=src.num))
        else:
            raise Exception(f'unsupported operands to or')

    @accept_lists_as_addresses
    def bxor(self, dest, src):
        if isinstance(dest, Rm32) and isinstance(src, R32):
            self.emit([0x31])
            self.emit(dest.modrm_bytes(reg=src.num))
        else:
            raise Exception(f'unsupported operands to xor')

    def bnot(self, reg):
        self.emit([0xf7, modrm(0b11, reg.num, 2)])

    def neg(self, reg):
        self.emit([0xf7, modrm(0b11, reg.num, 3)])

    @accept_lists_as_addresses
    def sub(self, dest, src):
        if isinstance(dest, Rm32) and isinstance(src, R32):
            self.emit([0x29])
            self.emit(dest.modrm_bytes(reg=src.num))

        elif isinstance(dest, Rm32) and isinstance(src, int):
            self.emit([0x81])
            self.emit(dest.modrm_bytes(reg=5))
            self.emit32(src)

        else:
            raise Exception('unsupported operands to sub')

    @accept_lists_as_addresses
    def imul(self, dest, src):
        if isinstance(dest, R32) and isinstance(src, Rm32):
            self.emit([0x0f, 0xaf])
            self.emit(src.modrm_bytes(reg=dest.num))
        else:
            raise Exception('unsupported operands to imul')

    @accept_lists_as_addresses
    def idiv(self, reg):
        if isinstance(reg, Rm32):
            self.emit([0xf7])
            self.emit(reg.modrm_bytes(reg=7))
        else:
            raise Exception('unsupported operands to idiv')

    @accept_lists_as_addresses
    def div(self, reg):
        if isinstance(reg, Rm32):
            self.emit([0xf7])
            self.emit(reg.modrm_bytes(reg=6))
        else:
            raise Exception('unsupported operands to div')

    @accept_lists_as_addresses
    def shl(self, dest, shift):
        if isinstance(dest, Rm32) and isinstance(shift, int):
            self.emit([0xc1])
            self.emit(dest.modrm_bytes(reg=4))
            self.emit([shift & 0xff])

        elif isinstance(dest, Rm32) and shift is CL:
            self.emit([0xd3])
            self.emit(dest.modrm_bytes(reg=4))

        else:
            raise Exception('unsupported operands to shl')

    @accept_lists_as_addresses
    def shr(self, dest, shift):
        if isinstance(dest, Rm32) and shift is CL:
            self.emit([0xd3])
            self.emit(dest.modrm_bytes(reg=5))
        else:
            raise Exception('unsupported operands to shr')

    @accept_lists_as_addresses
    def sar(self, dest, shift):
        if isinstance(dest, Rm32) and shift is CL:
            self.emit([0xd3])
            self.emit(dest.modrm_bytes(reg=7))
        else:
            raise Exception('unsupported operands to sar')

    def movsx(self, dest, src):
        if isinstance(dest, R32) and isinstance(src, R8):
            self.emit([0x0f, 0xbe, modrm(0b11, src.num, dest.num)])

        elif isinstance(dest, R32) and isinstance(src, R16):
            self.emit([0x0f, 0xbf, modrm(0b11, src.num, dest.num)])

        else:
            raise Exception('unsupported operands to movsx')

    def movzx(self, dest, src):
        if isinstance(dest, R32) and isinstance(src, R8):
            self.emit([0x0f, 0xb6, modrm(0b11, src.num, dest.num)])

        elif isinstance(dest, R32) and isinstance(src, R16):
            self.emit([0x0f, 0xb7, modrm(0b11, src.num, dest.num)])

        else:
            raise Exception('unsupported operands to movsx')

    @accept_lists_as_addresses
    def push(self, operand):
        if isinstance(operand, int):
            self.emit([0x68])
            self.emit32(operand)

        elif isinstance(operand, R32):
            self.emit([0x50 + operand.num])

        elif isinstance(operand, Rm32):
            self.emit([0xff])
            self.emit(operand.modrm_bytes(reg=6))

        else:
            raise Exception('unsupported operands to push')

    @accept_lists_as_addresses
    def pop(self, operand):
        if isinstance(operand, R32):
            self.emit([0x58 + operand.num])

        elif isinstance(operand, Rm32):
            self.emit([0x8f])
            self.emit(operand.modrm_bytes(reg=0))

        else:
            raise Exception('unsupported operands to pop')

    def rep_movsb(self):
        self.emit([0xf3, 0xa4])

    def cdq(self):
        self.emit([0x99])

    @accept_lists_as_addresses
    def movd(self, dest, src):
        if isinstance(dest, XMM) and isinstance(src, Rm32):
            self.emit([0x66, 0x0f, 0x6e])
            self.emit(src.modrm_bytes(reg=dest.num))

        elif isinstance(dest, Rm32) and isinstance(src, XMM):
            self.emit([0x66, 0x0f, 0x7e])
            self.emit(dest.modrm_bytes(reg=src.num))

        else:
            raise Exception('unsupported operands to movd')

    def addss(self, dest, src):
        if isinstance(dest, XMM) and isinstance(src, XMM):
            self.emit([0xf3, 0x0f, 0x58, modrm(0b11, src.num, dest.num)])
        else:
            raise Exception('unsupported operands to addss')

    def subss(self, dest, src):
        if isinstance(dest, XMM) and isinstance(src, XMM):
            self.emit([0xf3, 0x0f, 0x5c, modrm(0b11, src.num, dest.num)])
        else:
            raise Exception('unsupported operands to subss')

    def mulss(self, dest, src):
        if isinstance(dest, XMM) and isinstance(src, XMM):
            self.emit([0xf3, 0x0f, 0x59, modrm(0b11, src.num, dest.num)])
        else:
            raise Exception('unsupported operands to mulss')

    def divss(self, dest, src):
        if isinstance(dest, XMM) and isinstance(src, XMM):
            self.emit([0xf3, 0x0f, 0x5e, modrm(0b11, src.num, dest.num)])
        else:
            raise Exception('unsupported operands to divss')

    def cvtsi2ss(self, dest, src):
        if isinstance(dest, XMM) and isinstance(src, R32):
            self.emit([0xf3, 0x0f, 0x2a, modrm(0b11, src.num, dest.num)])
        else:
            raise Exception('unsupported operands to cvtsi2ss')

    def cvttss2si(self, dest, src):
        if isinstance(dest, R32) and isinstance(src, XMM):
            self.emit([0xf3, 0x0f, 0x2c, modrm(0b11, src.num, dest.num)])
        else:
            raise Exception('unsupported operands to cvttss2si')

    def ucomiss(self, dest, src):
        if isinstance(dest, XMM) and isinstance(src, XMM):
            self.emit([0x0f, 0x2e, modrm(0b11, src.num, dest.num)])
        else:
            raise Exception('unsupported operands to ucomiss')

    @accept_lists_as_addresses
    def fld(self, src):
        if isinstance(src, EffectiveAddress):
            self.emit([0xd9])
            self.emit(src.modrm_bytes(reg=0))
        else:
            raise Exception('unsupported operands to fld')

    @accept_lists_as_addresses
    def fild(self, src):
        if isinstance(src, EffectiveAddress):
            self.emit([0xdb])
            self.emit(src.modrm_bytes(reg=0))
        else:
            raise Exception('unsupported operands to fild')

    @accept_lists_as_addresses
    def fstp(self, dest):
        if isinstance(dest, int):
            self.emit([0xdd, 0xd8 + dest])
        elif isinstance(dest, EffectiveAddress):
            self.emit([0xd9])
            self.emit(dest.modrm_bytes(reg=3))
        else:
            raise Exception('unsupported operands to fstp')

    @accept_lists_as_addresses
    def fistp(self, dest):
        if isinstance(dest, EffectiveAddress):
            self.emit([0xdb])
            self.emit(dest.modrm_bytes(reg=3))
        else:
            raise Exception('unsupported operands to fstp')

    def faddp(self):
        self.emit([0xde, 0xc1])

    def fsubp(self):
        self.emit([0xde, 0xe9])

    def fmulp(self):
        self.emit([0xde, 0xc9])

    def fdivp(self):
        self.emit([0xde, 0xf9])

    def fcomip(self, i):
        self.emit([0xdf, 0xf0 + i])

    def syscall(self):
        self.emit([0x0f, 0x05])
