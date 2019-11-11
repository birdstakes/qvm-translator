class Reg:
    def __init__(self, parent):
        self.parent = parent                 # parent register allocator
        self.num = parent.get_free_num(self) # register number
        self.offset = None                   # stack offset if spilled

    def get(self):
        if self.num is None:
            self.num = self.parent.get_free_num(self)
            self.parent.unspill(self)
        return self.num

    def free(self):
        self.parent.free(self)

class RegAllocator:
    def __init__(self, spill_callback, unspill_callback, num_regs):
        self.spill_callback = spill_callback
        self.unspill_callback = unspill_callback
        self.num_regs = num_regs
        self.regs = [None]*num_regs
        self.spills = []
        self.next_spill = 0

    def new(self):
        return Reg(self)

    def free(self, reg):
        if reg in self.regs:
            self.regs[self.regs.index(reg)] = None
        if reg in self.spills:
            self.spills[self.spills.index(reg)] = None

    def spill(self, reg):
        self.spill_callback(reg)
        #reg.offset = self.get_free_offset(reg)
        #self.function.bb.code.append(IR(OP_SPILL, reg.num, reg.offset))
        #reg.num = None

    def unspill(self, reg):
        self.unspill_callback(reg)
        #self.function.bb.code.append(IR(OP_UNSPILL, reg.num, reg.offset))
        #self.spills[reg.offset] = None
        #reg.offset = None

    def spill_all(self):
        for reg in self.regs:
            if reg is not None:
                self.spill(reg)
        self.regs = [None]*self.num_regs
        self.next_spill = 0

    def get_free_num(self, reg):
        try:
            idx = self.regs.index(None)
            self.regs[idx] = reg
            return idx
        except ValueError:
            self.spill(self.regs[self.next_spill])
            self.regs[self.next_spill] = reg
            last_spill = self.next_spill
            self.next_spill = (self.next_spill + 1) % len(self.regs)
            return last_spill

    '''
    def get_free_offset(self, reg):
        try:
            idx = self.spills.index(None)
            self.spills[idx] = reg
            return idx
        except:
            self.spills.append(None)
            self.spills[-1] = reg
            return len(self.spills) - 1
    '''
