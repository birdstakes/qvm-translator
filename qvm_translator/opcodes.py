import enum


class Opcode(enum.IntEnum):
    UNDEF = 0
    IGNORE = 1
    BREAK = 2
    ENTER = 3
    LEAVE = 4
    CALL = 5
    PUSH = 6
    POP = 7
    CONST = 8
    LOCAL = 9
    JUMP = 10
    EQ = 11
    NE = 12
    LTI = 13
    LEI = 14
    GTI = 15
    GEI = 16
    LTU = 17
    LEU = 18
    GTU = 19
    GEU = 20
    EQF = 21
    NEF = 22
    LTF = 23
    LEF = 24
    GTF = 25
    GEF = 26
    LOAD1 = 27
    LOAD2 = 28
    LOAD4 = 29
    STORE1 = 30
    STORE2 = 31
    STORE4 = 32
    ARG = 33
    BLOCK_COPY = 34
    SEX8 = 35
    SEX16 = 36
    NEGI = 37
    ADD = 38
    SUB = 39
    DIVI = 40
    DIVU = 41
    MODI = 42
    MODU = 43
    MULI = 44
    MULU = 45
    BAND = 46
    BOR = 47
    BXOR = 48
    BCOM = 49
    LSH = 50
    RSHI = 51
    RSHU = 52
    NEGF = 53
    ADDF = 54
    SUBF = 55
    DIVF = 56
    MULF = 57
    CVIF = 58
    CVFI = 59


unary_ops = {
    Opcode.NEGI: "-",
    Opcode.NEGF: "-",
    Opcode.BCOM: "~",
    Opcode.CVIF: "(float)",
    Opcode.CVFI: "(int)",
    Opcode.SEX8: "(char)",
    Opcode.SEX16: "(short)",
}

binary_ops = {
    Opcode.ADD: "+",
    Opcode.ADDF: "+",
    Opcode.SUB: "-",
    Opcode.SUBF: "-",
    Opcode.MULI: "*",
    Opcode.MULU: "*",
    Opcode.MULF: "*",
    Opcode.DIVI: "/",
    Opcode.DIVU: "/",
    Opcode.DIVF: "/",
    Opcode.MODI: "%",
    Opcode.MODU: "%",
    Opcode.BAND: "&",
    Opcode.BOR: "|",
    Opcode.BXOR: "^",
    Opcode.LSH: "<<",
    Opcode.RSHI: ">>",
    Opcode.RSHU: ">>",
}

comparison_ops = {
    Opcode.EQ: "==",
    Opcode.EQF: "==",
    Opcode.NE: "!=",
    Opcode.NEF: "!=",
    Opcode.LTI: "<",
    Opcode.LTU: "<",
    Opcode.LTF: "<",
    Opcode.LEI: "<=",
    Opcode.LEU: "<",
    Opcode.LEF: "<=",
    Opcode.GTI: ">",
    Opcode.GTU: ">",
    Opcode.GTF: ">",
    Opcode.GEI: ">=",
    Opcode.GEU: ">=",
    Opcode.GEF: ">=",
}

comparison_inverse = {
    Opcode.EQ: Opcode.NE,
    Opcode.EQF: Opcode.NEF,
    Opcode.NE: Opcode.EQ,
    Opcode.NEF: Opcode.EQF,
    Opcode.LTI: Opcode.GEI,
    Opcode.LTU: Opcode.GEU,
    Opcode.LTF: Opcode.GEF,
    Opcode.LEI: Opcode.GTI,
    Opcode.LEU: Opcode.GTU,
    Opcode.LEF: Opcode.GTF,
    Opcode.GTI: Opcode.LEI,
    Opcode.GTU: Opcode.LEU,
    Opcode.GTF: Opcode.LEF,
    Opcode.GEI: Opcode.LTI,
    Opcode.GEU: Opcode.LTU,
    Opcode.GEF: Opcode.LTF,
}
