#Detects whether an app is using swizzling and prints all references
#@author LaurieWired
#@category iOS

from ghidra.program.model.symbol import SymbolType

def find_swizzling():
    # List of potential swizzling related methods
    swizzling_methods = [
        "method_exchangeImplementations",
        "class_getInstanceMethod",
        "class_getClassMethod",
        "method_setImplementation"
    ]
    
    # Find the addresses of all functions containing the substrings from swizzling_methods
    swizzling_symbols = []
    for symbol in currentProgram.getSymbolTable().getAllSymbols(True):
        if symbol.getSymbolType() == SymbolType.FUNCTION and any(method in symbol.getName() for method in swizzling_methods):
            swizzling_symbols.append(symbol)

    if not swizzling_symbols:
        print("No swizzling found")
        return

    for swizzling_symbol in swizzling_symbols:
        # Enumerate all references to this function
        references = list(currentProgram.getReferenceManager().getReferencesTo(swizzling_symbol.getAddress()))

        if not references:
            print("Swizzling method {} located at address {}, but had no references".format(swizzling_symbol.getName(), swizzling_symbol.getAddress()))
            continue

        print("Swizzling method {} located at address {}, with references:".format(swizzling_symbol.getName(), swizzling_symbol.getAddress()))
        for ref in references:
            print("Address: {}".format(ref.getFromAddress()))

find_swizzling()
