import lldb
import shlex
import struct

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

def load_symbol(target, symbol):
	process = target.GetProcess()
	syms = target.FindSymbols(symbol)
	error = lldb.SBError()
	if len(syms.symbols):
		symbol = syms.symbols[0]
		size = int(symbol.end_addr) - int(symbol.addr)
		val = process.ReadMemory(int(symbol.addr), size, error)
		if error.Success():
			return bytearray_to_int(val, size)
		else:
			return error
	else:
		return None

SYMBOLS = {
	'major': ['_ZN2v88internal7Version6major_E'],
	'minor': ['_ZN2v88internal7Version6minor_E'],
	'build': ['_ZN2v88internal7Version6build_E'],
	'patch': ['_ZN2v88internal7Version6patch_E'],

	'V8_OFF_FP_CONTEXT': ['v8dbg_off_fp_context'],
	'V8_OFF_FP_FUNCTION': ['v8dbg_off_fp_function'],
	'V8_OFF_FP_MARKER': ['v8dbg_off_fp_marker'],
	'V8_OFF_FP_ARGS': ['v8dbg_off_fp_args'],

	'V8_FirstNonstringType': ['v8dbg_FirstNonstringType'],
	'V8_IsNotStringMask': ['v8dbg_IsNotStringMask'],
	'V8_StringTag': ['v8dbg_StringTag'],
	'V8_NotStringTag': ['v8dbg_NotStringTag'],
	'V8_StringEncodingMask': ['v8dbg_StringEncodingMask'],
	'V8_TwoByteStringTag': ['v8dbg_TwoByteStringTag'],
	'V8_AsciiStringTag': ['v8dbg_AsciiStringTag'],
	'V8_StringRepresentationMask': ['v8dbg_StringRepresentationMask'],
	'V8_SeqStringTag': ['v8dbg_SeqStringTag'],
	'V8_ConsStringTag': ['v8dbg_ConsStringTag'],
	'V8_SlicedStringTag': ['v8dbg_SlicedStringTag', None, 0x3],

	'V8_ExternalStringTag': ['v8dbg_ExternalStringTag'],
	'V8_FailureTag': ['v8dbg_FailureTag'],
	'V8_FailureTagMask': ['v8dbg_FailureTagMask'],
	'V8_HeapObjectTag': ['v8dbg_HeapObjectTag'],
	'V8_HeapObjectTagMask': ['v8dbg_HeapObjectTagMask'],
	'V8_SmiTag': ['v8dbg_SmiTag'],
	'V8_SmiTagMask': ['v8dbg_SmiTagMask'],
	'V8_SmiValueShift': ['v8dbg_SmiValueShift'],
	'V8_SmiShiftSize': ['v8dbg_SmiShiftSize', None, 0],

	'V8_PointerSizeLog2': ['v8dbg_PointerSizeLog2'],

	'V8_DICT_SHIFT': ['v8dbg_dict_shift', '3.13', 24 ],
	'V8_DICT_PREFIX_SIZE': ['v8dbg_dict_prefix_size', '3.11', 2 ],
	'V8_DICT_ENTRY_SIZE': ['v8dbg_dict_entry_size', '3.11', 3],
	'V8_DICT_START_INDEX': ['v8dbg_dict_start_index', '3.11', 3],
	'V8_ISSHARED_SHIFT': ['v8dbg_isshared_shift', '3.11', 0],
	'V8_PROP_IDX_FIRST': ['v8dbg_prop_idx_first'],
	'V8_PROP_TYPE_FIELD': ['v8dbg_prop_type_field'],
	'V8_PROP_FIRST_PHANTOM': ['v8dbg_prop_type_first_phantom'],
	'V8_PROP_TYPE_MASK': ['v8dbg_prop_type_mask'],
	'V8_PROP_IDX_CONTENT': ['v8dbg_prop_idx_content', None],
	'V8_PROP_DESC_KEY': ['v8dbg_prop_desc_key', None, 0],
	'V8_PROP_DESC_DETAILS': ['v8dbg_prop_desc_details', None, 1],
	'V8_PROP_DESC_VALUE': ['v8dbg_prop_desc_value', None, 2],
	'V8_PROP_DESC_SIZE': ['v8dbg_prop_desc_size', None, 3],
	'V8_TRANSITIONS_IDX_DESC': ['v8dbg_transitions_idx_descriptors', None ],

	'V8_ELEMENTS_KIND_SHIFT': ['v8dbg_elements_kind_shift', None, 3],
	'V8_ELEMENTS_KIND_BITCOUNT': ['v8dbg_elements_kind_bitcount', None, 5],
	'V8_ELEMENTS_FAST_ELEMENTS': ['v8dbg_elements_fast_elements', None, 2],
	'V8_ELEMENTS_FAST_HOLEY_ELEMENTS': ['v8dbg_elements_fast_holey_elements', None, 3],
	'V8_ELEMENTS_DICTIONARY_ELEMENTS': ['v8dbg_elements_dictionary_elements', None, 6],
}

FRAMETYPE = {}
CLASS = {}
TYPE = {}

def v8_is_smi(addr, internal_dict):
	smi = internal_dict['V8_SmiTag']
	mask = internal_dict['V8_SmiTagMask']
	return ((addr & mask) == smi)

def v8_smi(addr, internal_dict):
	val = internal_dict['V8_SmiValueShift']
	sze = internal_dict['V8_SmiShiftSize']
	return (addr >> (val + sze))

def read_type(process, addr, internal_dict):
	heapoff = CLASS['HeapObject']['fields']['map']['offset'] - 1
	mask = internal_dict['V8_HeapObjectTagMask']
	tag = internal_dict['V8_HeapObjectTag']
	aoff = CLASS['Map']['fields']['instance_attributes']['offset'] - 1

	error = lldb.SBError()

	maddr = process.ReadPointerFromMemory(addr + heapoff, error)

	if not error.Success():
		return error

	if (maddr & mask) != tag:
		return False

	hbyte = process.ReadMemory(maddr + aoff, 1, error)

	if not error.Success():
		return error

	hbyte = bytearray_to_uint(hbyte, 1)

	return TYPE[hbyte]

def read_heap_smi(process, addr, off, internal_dict):
	error = lldb.SBError()
	ptr = process.ReadPointerFromMemory(addr + off, error)

	if not error.Success():
		return error

	return v8_smi(ptr, internal_dict)

def jstr_print_seq(process, addr, internal_dict):
	strlen = CLASS['String']['fields']['length']['offset'] - 1
	slen = read_heap_smi(process, addr, strlen, internal_dict)
	if isinstance(slen, lldb.SBError):
		return slen

	if not slen:
		return 'anonymous'

	## XXX
	#off = CLASS['SeqAsciiString']['fields']['chars']['offset'] - 1
	off = 23

	error = lldb.SBError()

	blob = process.ReadMemory(addr + off, slen, error)

	if not error.Success():
		return error

	return blob
	
def jstr_print(process, addr, internal_dict):
	typename = read_type(process, addr, internal_dict)
	if 'SeqAsciiString' in typename:
		typename = jstr_print_seq(process, addr, internal_dict)
	return typename

def jsfunc_name(process, internal_dict, pointer):
	error = lldb.SBError()
	off = CLASS['SharedFunctionInfo']['fields']['name']['offset'] - 1

	fstr = process.ReadPointerFromMemory(pointer + off, error)

	if not error.Success():
		return error

	name = jstr_print(process, fstr, internal_dict)

	return name

def jsstack_frame(debugger, result, internal_dict, target, thread, fp):
	error = lldb.SBError()
	process = target.GetProcess()
	off = fp + internal_dict['V8_OFF_FP_CONTEXT']
	pointer = process.ReadPointerFromMemory(off, error)

	if not error.Success():
		print >> result, 'error: ', error
		return

	if v8_is_smi(pointer, internal_dict):
		smi = v8_smi(pointer, internal_dict)
		ft = FRAMETYPE.get(smi, None)
		if ft:
			return {
				'fp': fp,
				'val': '<{ft}>'.format(ft=ft),
			}
	off = fp + internal_dict['V8_OFF_FP_MARKER']
	pointer = process.ReadPointerFromMemory(off, error)

	if not error.Success():
		print >> result, 'error: ', error
		return

	if v8_is_smi(pointer, internal_dict):
		smi = v8_smi(pointer, internal_dict)
		ft = FRAMETYPE.get(smi, None)
		if ft:
			return {
				'fp': fp,
				'val': '<{ft}>'.format(ft=ft),
			}

	off = fp + internal_dict['V8_OFF_FP_FUNCTION']
	pointer = process.ReadPointerFromMemory(off, error)

	if not error.Success():
		print >> result, 'error: ', error
		return
	
	typename = read_type(process, pointer, internal_dict)

	if isinstance(typename, lldb.SBError):
		print >> result, typename
		return

	if not typename:
		#print >> result, '{addr:#016x} not a heap object'.format(addr=pointer)
		return

	if 'Code' in typename:
		return {
			'fp': fp,
			'val': 'internal (Code: {pointer:#016x})'.format(pointer= pointer),
		}

	off = CLASS['JSFunction']['fields']['shared']['offset'] - 1

	func = process.ReadPointerFromMemory(pointer + off, error)

	if not error.Success():
		return error

	funcname = jsfunc_name(process, internal_dict, func)

	if isinstance(funcname, lldb.SBError):
		return funcname

	return {
		'fp': fp,
		'val': '<%s>' % funcname
	}
	
def jsframe(debugger, command, result, internal_dict):
	args = shlex.split(command)
	fp = int(args[0], 16)
	target = debugger.GetSelectedTarget()
	thread = target.process.GetSelectedThread()
	frame = jsstack_frame(debugger, result, internal_dict, target, thread, fp)
	print >> result, frame

def jsstack_thread(debugger, result, internal_dict, target, thread):
	depth = thread.GetNumFrames()

	mods = get_module_names(thread)
	funcs = get_function_names(thread)
	symbols = get_symbol_names(thread)
	files = get_filenames(thread)
	lines = get_line_numbers(thread)
	addrs = get_pc_addresses(thread)

	for i in range(depth):
		frame = thread.GetFrameAtIndex(i)
		function = frame.GetFunction()

		load_addr = addrs[i].GetLoadAddress(target)
		if not function:
			file_addr = addrs[i].GetFileAddress()
			start_addr = frame.GetSymbol().GetStartAddress().GetFileAddress()
			symbol_offset = file_addr - start_addr
			mod=mods[i]
			if not mod:
				f = jsstack_frame(debugger, result, internal_dict, target, thread, frame.fp)
			else:
				f = {
					'fp': load_addr,
					'val': '{mod}`{symbol} + {offset}'.format(mod=mod, symbol=symbols[i], offset=symbol_offset),
				}

			if isinstance(f, lldb.SBError):
				print >> result, f
			elif f:
				print >> result, '  frame #{num}: {fp:#016x} {val}'.format(num=i, fp=f['fp'], val=f['val'])
			else:
				print >> result, '  frame #{num}: {fp:#016x} skipped'.format(num=i, fp=load_addr)
				#print >> result, '  frame #{num}: {addr:#016x} {mod}`{symbol} + {offset}'.format(num=i, addr=load_addr, mod=mod, symbol=symbols[i], offset=symbol_offset)
		else:
            		print >> result, '  frame #{num}: {addr:#016x} {mod}`{func} at {file}:{line} {args}'.format(
                		num=i, addr=load_addr, mod=mods[i],
				func='%s [inlined]' % funcs[i] if frame.IsInlined() else funcs[i],
				file=files[i], line=lines[i],
				args=get_args_as_string(frame, showFuncName=False) if not frame.IsInlined() else '()')

def jsstack(debugger, command, result, internal_dict):
	target = debugger.GetSelectedTarget()
	process = target.GetProcess()

	threads = process.GetNumThreads()

	for i in range(threads):
		print >> result, 'thread #{i}'.format(i=i)
		jsstack_thread(debugger, result, internal_dict, target, process.GetThreadAtIndex(i))


# And the initialization code to add your commands 
def __lldb_init_module(debugger, internal_dict):
	target = debugger.GetSelectedTarget()
	delay = []
	for key, value in SYMBOLS.iteritems():
		ret = load_symbol(target, value[0])
		if isinstance(ret, lldb.SBError):
			print 'failed to load symbol: ', ret
			return
		elif ret is None:
			if len(value) == 3:
				ret = value[2]
			elif len(value) == 2:
				pass
			else:
				print 'failed to load symbol: ', key

		if ret is not None:
			internal_dict[key] = ret

	for i in range(target.GetNumModules()):
		mod = target.GetModuleAtIndex(i)
		for j in range(mod.GetNumSymbols()):
			sym = mod.GetSymbolAtIndex(j)
			if 'v8dbg_frametype_' in sym.name:
				val = load_symbol(target, sym.name)
				key = sym.name.replace('v8dbg_frametype_', '')
				FRAMETYPE[key] = val
				FRAMETYPE[val] = key
			elif 'v8dbg_parent_' in sym.name:
				val = load_symbol(target, sym.name)
				key = sym.name.replace('v8dbg_parent_', '').split('__')
				parent = key[1]
				child = key[0]
				parent_klass = CLASS.get(parent, { 'name': parent, 'fields': {} })
				child_klass = CLASS.get(child, { 'name': child, 'parent': parent_klass, 'fields': {} })

				child_klass['parent'] = parent_klass

				CLASS[parent] = parent_klass
				CLASS[child] = child_klass
			elif 'v8dbg_class_' in sym.name:
				val = load_symbol(target, sym.name)
				key = sym.name.replace('v8dbg_class_', '').split('__')


				kname = key[0]
				field = key[1]
				ktype = key[2]

				klass = CLASS.get(kname, { 'name': kname, 'fields': {} })

				klass['fields'][field] = {
					'type': ktype,
					'name': field,
					'offset': val,
				}
				pass
			elif 'v8dbg_type_' in sym.name:
				val = load_symbol(target, sym.name)
				key = sym.name.replace('v8dbg_type_', '')
				TYPE[key] = val
				TYPE[val] = key



	major = internal_dict['major']
	minor = internal_dict['minor']
	build = internal_dict['build']
	patch = internal_dict['patch']

	print 'Identified V8 Version {major}.{minor}.{build}.{patch}'.format(**internal_dict)

	debugger.HandleCommand('command script add -f v8.jsstack jsstack')
	debugger.HandleCommand('command script add -f v8.jsframe jsframe')
