# qvm-translator

Translate Quake 3 qvms to x86 Ghidra projects

## Usage

```
translate.py mycoolqvm.qvm [mycoolqvm.map]
```

This creates `mycoolqvm.xml` and `mycoolqvm.bytes`. `mycoolqvm.xml` can then be imported into Ghidra.

There will be a giant array called `__instruction_addresses` mapping qvm instructions to their new addresses in the x86 code. This can be used to annotate function pointers with a script like this:

```python
from ghidra.program.model.listing import Data, Instruction
from ghidra.program.model.symbol import RefType, SourceType

def qvm_to_x86(addr):
    instruction_addresses = getSymbol('__instruction_addresses', None).getAddress()
    return getInt(instruction_addresses.add(addr * 4))

cu = currentProgram.getListing().getCodeUnitContaining(currentAddress)
if isinstance(cu, Instruction):
    index = currentLocation.getOperandIndex()
    qvm_address = cu.getScalar(index).getUnsignedValue()
    x86_addr = qvm_to_x86(qvm_address)
    setPreComment(currentAddress, '{@symbol %x}' % x86_addr)
    cu.addOperandReference(index, toAddr(x86_addr), RefType.DATA, SourceType.USER_DEFINED)
else:
    qvm_address = getInt(currentAddress)
    x86_addr = qvm_to_x86(qvm_address)
    data = getDataContaining(currentAddress)
    component = data.getComponent(currentLocation.getComponentPath())
    createMemoryReference(component, toAddr(x86_addr), RefType.DATA)
```

Place the cursor on a function pointer operand in the disassembly and run the script to create a reference to the function. A comment will also be added so that the reference can be seen and clicked in the decompiler view.

Before:

![Before](https://i.imgur.com/pBpluk0.png)

After:

![After](https://i.imgur.com/5KkFys6.png)
