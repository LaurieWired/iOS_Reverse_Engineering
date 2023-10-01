#Demangles Swift class, function, and variable names
#@author LaurieWired
#@category Swift
#@keybinding 
#@menupath Tools.Swift.Demangle Swift Names
#@toolbar 

# NOTES:
# Requires Swift to be installed on the machine
# Takes some time to run for larger applications

from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SymbolType
import subprocess
import platform

def demangle_swift_name(mangled_name):

    # Determine the correct command based on the OS
    if platform.system() == "Darwin":
        cmd = 'xcrun swift-demangle --simplified --compact'
    else:
        cmd = 'swift-demangle --simplified --compact'

    # Run as subprocess
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    proc.stdin.write(mangled_name)
    proc.stdin.close()
    demangled = proc.stdout.read().strip()
    proc.wait()
    
    # Return demangler output. If it's not a Swift type, it will just return original name
    return demangled

def clean_demangled_name(name):

    # Remove everything after the opening parenthesis (removes function arguments)
    name = name.split("(")[0]
    
    # Replace spaces and other undesired characters
    name = name.replace(" ", "_")
    name = name.replace("<", "_")
    name = name.replace(">", "_")

    return name

def beautify_swift_program():

    # Demangle function names
    print("Renaming functions")
    for func in currentProgram.getFunctionManager().getFunctions(True):
        demangled_name = demangle_swift_name(func.getName())
        cleaned_name = clean_demangled_name(demangled_name)
        
        if cleaned_name != func.getName():
            print("Original: {}, New: {}".format(func.getName(), cleaned_name))
            
            # Set new function name and comment
            func.setComment("Original: {}\nDemangled: {}".format(func.getName(), demangled_name))
            func.setName(cleaned_name, ghidra.program.model.symbol.SourceType.USER_DEFINED)

    # Demangle labels if they are Swift types
    print("\nRenaming labels")
    for symbol in currentProgram.getSymbolTable().getAllSymbols(True):
        if symbol.getSymbolType() == SymbolType.LABEL:
            demangled_name = demangle_swift_name(symbol.getName())
            cleaned_name = clean_demangled_name(demangled_name)
            
            if cleaned_name != symbol.getName():
                print("Original: {}, New: {}".format(symbol.getName(), cleaned_name))
                
                # Set new label name and comment
                # Ghidra already also renames pointers to labels as well
                currentProgram.getListing().setComment(symbol.getAddress(), ghidra.program.model.listing.CodeUnit.EOL_COMMENT, "Original: {}\nDemangled: {}".format(symbol.getName(), demangled_name))
                symbol.setName(cleaned_name, ghidra.program.model.symbol.SourceType.USER_DEFINED)

beautify_swift_program()
