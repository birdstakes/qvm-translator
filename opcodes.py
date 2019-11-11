UNDEF      = 0
IGNORE     = 1
BREAK      = 2
ENTER      = 3
LEAVE      = 4
CALL       = 5
PUSH       = 6
POP        = 7
CONST      = 8
LOCAL      = 9
JUMP       = 10
EQ         = 11
NE         = 12
LTI        = 13
LEI        = 14
GTI        = 15
GEI        = 16
LTU        = 17
LEU        = 18
GTU        = 19
GEU        = 20
EQF        = 21
NEF        = 22
LTF        = 23
LEF        = 24
GTF        = 25
GEF        = 26
LOAD1      = 27
LOAD2      = 28
LOAD4      = 29
STORE1     = 30
STORE2     = 31
STORE4     = 32
ARG        = 33
BLOCK_COPY = 34
SEX8       = 35
SEX16      = 36
NEGI       = 37
ADD        = 38
SUB        = 39
DIVI       = 40
DIVU       = 41
MODI       = 42
MODU       = 43
MULI       = 44
MULU       = 45
BAND       = 46
BOR        = 47
BXOR       = 48
BCOM       = 49
LSH        = 50
RSHI       = 51
RSHU       = 52
NEGF       = 53
ADDF       = 54
SUBF       = 55
DIVF       = 56
MULF       = 57
CVIF       = 58
CVFI       = 59

mnemonics={}
mnemonics[UNDEF]      = 'UNDEF'
mnemonics[IGNORE]     = 'IGNORE'
mnemonics[BREAK]      = 'BREAK'
mnemonics[ENTER]      = 'ENTER'
mnemonics[LEAVE]      = 'LEAVE'
mnemonics[CALL]       = 'CALL'
mnemonics[PUSH]       = 'PUSH'
mnemonics[POP]        = 'POP'
mnemonics[CONST]      = 'CONST'
mnemonics[LOCAL]      = 'LOCAL'
mnemonics[JUMP]       = 'JUMP'
mnemonics[EQ]         = 'EQ'
mnemonics[NE]         = 'NE'
mnemonics[LTI]        = 'LTI'
mnemonics[LEI]        = 'LEI'
mnemonics[GTI]        = 'GTI'
mnemonics[GEI]        = 'GEI'
mnemonics[LTU]        = 'LTU'
mnemonics[LEU]        = 'LEU'
mnemonics[GTU]        = 'GTU'
mnemonics[GEU]        = 'GEU'
mnemonics[EQF]        = 'EQF'
mnemonics[NEF]        = 'NEF'
mnemonics[LTF]        = 'LTF'
mnemonics[LEF]        = 'LEF'
mnemonics[GTF]        = 'GTF'
mnemonics[GEF]        = 'GEF'
mnemonics[LOAD1]      = 'LOAD1'
mnemonics[LOAD2]      = 'LOAD2'
mnemonics[LOAD4]      = 'LOAD4'
mnemonics[STORE1]     = 'STORE1'
mnemonics[STORE2]     = 'STORE2'
mnemonics[STORE4]     = 'STORE4'
mnemonics[ARG]        = 'ARG'
mnemonics[BLOCK_COPY] = 'BLOCK_COPY'
mnemonics[SEX8]       = 'SEX8'
mnemonics[SEX16]      = 'SEX16'
mnemonics[NEGI]       = 'NEGI'
mnemonics[ADD]        = 'ADD'
mnemonics[SUB]        = 'SUB'
mnemonics[DIVI]       = 'DIVI'
mnemonics[DIVU]       = 'DIVU'
mnemonics[MODI]       = 'MODI'
mnemonics[MODU]       = 'MODU'
mnemonics[MULI]       = 'MULI'
mnemonics[MULU]       = 'MULU'
mnemonics[BAND]       = 'BAND'
mnemonics[BOR]        = 'BOR'
mnemonics[BXOR]       = 'BXOR'
mnemonics[BCOM]       = 'BCOM'
mnemonics[LSH]        = 'LSH'
mnemonics[RSHI]       = 'RSHI'
mnemonics[RSHU]       = 'RSHU'
mnemonics[NEGF]       = 'NEGF'
mnemonics[ADDF]       = 'ADDF'
mnemonics[SUBF]       = 'SUBF'
mnemonics[DIVF]       = 'DIVF'
mnemonics[MULF]       = 'MULF'
mnemonics[CVIF]       = 'CVIF'
mnemonics[CVFI]       = 'CVFI'

unary_ops = {
    NEGI: '-', NEGF: '-',
    BCOM: '~',
    CVIF: '(float)',
    CVFI: '(int)',
    SEX8: '(char)',
    SEX16: '(short)',
}

binary_ops = {
    ADD: '+', ADDF: '+',
    SUB: '-', SUBF: '-',
    MULI: '*', MULU: '*', MULF: '*',
    DIVI: '/', DIVU: '/', DIVF: '/',
    MODI: '%', MODU: '%',
    BAND: '&',
    BOR: '|',
    BXOR: '^',
    LSH: '<<',
    RSHI: '>>', RSHU: '>>',
}

comparison_ops = {
    EQ: '==', EQF: '==',
    NE: '!=', NEF: '!=',
    LTI: '<', LTU: '<', LTF: '<',
    LEI: '<=', LEU: '<', LEF: '<=',
    GTI: '>', GTU: '>', GTF: '>',
    GEI: '>=', GEU: '>=', GEF: '>=',
}

comparison_inverse = {
    EQ: NE, EQF: NEF,
    NE: EQ, NEF: EQF,
    LTI: GEI, LTU: GEU, LTF: GEF,
    LEI: GTI, LEU: GTU, LEF: GTF,
    GTI: LEI, GTU: LEU, GTF: LEF,
    GEI: LTI, GEU: LTU, GEF: LTF,
}
