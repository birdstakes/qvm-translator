#Reload translated qvm code segment
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 

from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.app.cmd.memory import DeleteBlockCmd
from ghidra.app.util import Option
from ghidra.app.util.bin import RandomAccessByteProvider
from ghidra.app.util.importer import MessageLog
from ghidra.app.util.opinion import BinaryLoader, LoadSpec
from ghidra.program.model.symbol import SourceType
from java.io import File

# TODO: dialog box
code_segment_filename = 'C:/Users/Josh/Desktop/bla'
symbols_filename = 'C:/Users/Josh/Desktop/bla_symbols'

class SavedSignature:
    def __init__(self, function):
        self.signature = function.getSignature()
        self.custom_ret_storage = function.hasCustomVariableStorage()
        if self.custom_ret_storage:
            self.ret_storage = function.getReturn().getVariableStorage()
            self.ret_type = function.getReturnType()

    def apply_to(self, function):
        function.setCallingConvention('__cdecl')
        cmd = ApplyFunctionSignatureCmd(function.getEntryPoint(), self.signature, SourceType.USER_DEFINED, False, True)
        state.getTool().execute(cmd, currentProgram)
        if self.custom_ret_storage:
            function.setCustomVariableStorage(True)
            function.setReturn(self.ret_type, self.ret_storage, SourceType.USER_DEFINED)

code_block = getMemoryBlock('code')
instruction_addresses = getSymbols('__instruction_addresses', None)[0].getAddress()

functions = set()
function = getFirstFunction()
while function is not None:
    functions.add(function)
    function = getFunctionAfter(function)

# find functions with qvm addresses
numbered_signatures = []
i = 0
while instruction_addresses.add(i * 4) < code_block.getEnd():
    address = toAddr(getInt(instruction_addresses.add(i * 4)))
    function = getFunctionAt(address)
    if function is not None:
        if function in functions:
            #print 'adding numbered signature', hex(i), function
            functions.remove(function)
            numbered_signatures.append((i, SavedSignature(function)))
    i += 1

# find any remaining functions (syscalls and any helper functions)
named_signatures = []
for function in functions:
    #print 'adding named signature', function
    named_signatures.append((function.name, SavedSignature(function)))

# delete code segment
cmd = DeleteBlockCmd([code_block.getStart()], None)
state.getTool().execute(cmd, currentProgram)

# create new code segment from file
provider = RandomAccessByteProvider(File(code_segment_filename))
loader = BinaryLoader()
loadspec = LoadSpec(loader, 0, False)
options = loader.getDefaultOptions(provider, loadspec, currentProgram, True)
messagelog = MessageLog()

for option in options:
    if option.getName() == loader.OPTION_NAME_BASE_ADDR:
        option.setValue(toAddr(0x10000000))
    elif option.getName() == loader.OPTION_NAME_BLOCK_NAME:
        option.setValue('code')

loader.loadInto(provider, loadspec, options, messagelog, currentProgram, monitor)

# load symbols from file so we can find new __instruction_pointers
for line in file(symbols_filename):
    pieces = line.split()
    address = toAddr(long(pieces[1], 16))
    createLabel(address, pieces[0], False)

instruction_addresses = getSymbols('__instruction_addresses', None)[0].getAddress()

# apply signatures to functions with qvm addresses
for (i, signature) in numbered_signatures:
    address = toAddr(getInt(instruction_addresses.add(i * 4)))
    disassemble(address)
    function = createFunction(address, None)

    # function could have already been created during autoanalysis of
    # another function we created earlier
    if function is None:
        function = getFunctionAt(address)

    if function is not None:
        signature.apply_to(function)
        #print 'applied numbered signature', hex(i), function
    else:
        print 'failed to apply numbered signature', hex(i)

# apply signatures to remaining functions if their name is in the list
for (name, signature) in named_signatures:
    function = getFunction(name)
    if function is not None:
        signature.apply_to(function)
        #print 'applied named signature', name, function
    else:
        print 'failed to apply named signature', name

# saving stack variable names and types could also be useful since they shouldn't really change?
# though maybe function args and spilling would make that not work?
