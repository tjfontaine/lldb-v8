
def bytearray_to_int(bytes, bytesize):
    """Utility function to convert a bytearray into an integer.

    It interprets the bytearray in the little endian format. For a big endian
    bytearray, just do ba.reverse() on the object before passing it in.
    """
    import struct

    # Little endian followed by a format character.
    template = "<%c"
    if bytesize == 1:
        fmt = template % 'b'
    elif bytesize == 2:
        fmt = template % 'h'
    elif bytesize == 4:
        fmt = template % 'i'
    elif bytesize == 8:
        fmt = template % 'q'
    else:
        return None

    unpacked = struct.unpack(fmt, str(bytes))
    return unpacked[0]

def bytearray_to_uint(bytes, bytesize):
    """Utility function to convert a bytearray into an integer.

    It interprets the bytearray in the little endian format. For a big endian
    bytearray, just do ba.reverse() on the object before passing it in.
    """
    import struct

    # Little endian followed by a format character.
    template = "<%c"
    if bytesize == 1:
        fmt = template % 'B'
    elif bytesize == 2:
        fmt = template % 'H'
    elif bytesize == 4:
        fmt = template % 'I'
    elif bytesize == 8:
        fmt = template % 'Q'
    else:
        return None

    unpacked = struct.unpack(fmt, str(bytes))
    return unpacked[0]

def get_function_names(thread):
    """
    Returns a sequence of function names from the stack frames of this thread.
    """
    def GetFuncName(i):
        return thread.GetFrameAtIndex(i).GetFunctionName()

    return map(GetFuncName, range(thread.GetNumFrames()))


def get_symbol_names(thread):
    """
    Returns a sequence of symbols for this thread.
    """
    def GetSymbol(i):
        return thread.GetFrameAtIndex(i).GetSymbol().GetName()

    return map(GetSymbol, range(thread.GetNumFrames()))


def get_pc_addresses(thread):
    """
    Returns a sequence of pc addresses for this thread.
    """
    def GetPCAddress(i):
        return thread.GetFrameAtIndex(i).GetPCAddress()

    return map(GetPCAddress, range(thread.GetNumFrames()))


def get_filenames(thread):
    """
    Returns a sequence of file names from the stack frames of this thread.
    """
    def GetFilename(i):
        return thread.GetFrameAtIndex(i).GetLineEntry().GetFileSpec().GetFilename()

    return map(GetFilename, range(thread.GetNumFrames()))


def get_line_numbers(thread):
    """
    Returns a sequence of line numbers from the stack frames of this thread.
    """
    def GetLineNumber(i):
        return thread.GetFrameAtIndex(i).GetLineEntry().GetLine()

    return map(GetLineNumber, range(thread.GetNumFrames()))


def get_module_names(thread):
    """
    Returns a sequence of module names from the stack frames of this thread.
    """
    def GetModuleName(i):
        return thread.GetFrameAtIndex(i).GetModule().GetFileSpec().GetFilename()

    return map(GetModuleName, range(thread.GetNumFrames()))


def get_stack_frames(thread):
    """
    Returns a sequence of stack frames for this thread.
    """
    def GetStackFrame(i):
        return thread.GetFrameAtIndex(i)

    return map(GetStackFrame, range(thread.GetNumFrames()))

def get_args_as_string(frame, showFuncName=True):
    """
    Returns the args of the input frame object as a string.
    """
    # arguments     => True
    # locals        => False
    # statics       => False
    # in_scope_only => True
    vars = frame.GetVariables(True, False, False, True) # type of SBValueList
    args = [] # list of strings
    for var in vars:
      args.append("(%s)%s=%s" % (var.GetTypeName(), var.GetName(), var.GetValue()))

    if frame.GetFunction():
      name = frame.GetFunction().GetName()
    elif frame.GetSymbol():
      name = frame.GetSymbol().GetName()
    else:
      name = ""
    if showFuncName:
      return "%s(%s)" % (name, ", ".join(args))
    else:
      return "(%s)" % (", ".join(args))
