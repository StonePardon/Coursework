from idautils import *
from idaapi import *
import myregister

{
	# parsing of decompiler argument string
	# it look like  void __usercall fooo(__int64 a1@<rbp>, __int64 a2@<rdi>)
	# first words - returned data type(not intresting)
	# next is call calling convention 
	# then the name and sometimes the location of returns
	# brackes contain return values - type and name
	# for special CC - usercall, all input values have have special constructions
	# (struc_1 s@<0:rdi.1, 2:rdi^2.2, 4:rdi^4.1, 8:rsi.4>) structures : 
	 # argoff:register^regoff.size 
	 #  	argoff - offset within the argument
	 #  	register - register name used to pass part of the argument
	 #  	regoff - offset within the register
	 #  	size - number of bytes
	 #  or argoff:^stkoff.size
	 #  	argoff - offset within the argument
	 #  	stkoff - offset in the stack frame (the first stack argument is at offset 0)
	 #  	size - number of bytes
	# (int x, int y@<esi>) stack and register
}

def take_arg(str_input):
    arg = []
    k = len(str_input)
    if str_input[k - 2] == '(' or str_input[k - 5 : k - 1] == "void":
    	return None
    str_input = str_input[str_input.rfind("(") + 1: -1]
    while str_input.rfind(", ") != -1:
        i = str_input.rfind(", ")
        j = str_input.rfind('*')
        if j == -1:
            j = str_input.rfind(' ') - 1
        arg.append(str_input[i + 2:j + 1])
        str_input = str_input[:i]
    j = str_input.rfind('*')
    if j == -1:
        j = str_input.rfind(' ') - 1
    arg.append(str_input[:j + 1])
    arg.reverse()
    return arg



def argloc_info(data):
	# input format : type offset (register(s) name(s))
    if data.is_stkoff():
        offset = data.stkoff()
        rez = "stack "
        rez += str(offset)
        return rez
    if data.is_ea():
        ea = data.get_ea()
        rez = "global "
        rez += str(ea)
        return rez
    if data.is_reg1():
        regnum = data.reg1()
        rez = "reg1 "
        rez += str(data.regoff()) + " " + myregister.REG[regnum]
        return rez
    if data.is_reg2():
        regnum1 = data.reg1()
        regnum2 = data.reg2()
        rez = "reg2 "
        rez += str(data.regoff()) + " " + myregister.REG[regnum1] 
        rez += " " + myregister.REG[regnum2]
        return rez
    if data.is_rrel():
    	rrel_data = data.get_rrel()
        regnum = rrel_data.reg()
        rez = "rrel "
        rez += str(rrel_data.off()) + " " + myregister.REG[regnum]
        return rez
    if data.is_scattered():
    	# i don't know, what to do in this case
    	scatt_data = data.scattered()
        rez = "scattered " 
        return rez

#print "Hello? world!"
fname = idc.AskStr(".txt", "Enter a file name")
if fname == None:
    print "Defalt file name is ida_for_pro.txt"
    fname = "ida_for_pro.txt"
else:
	print fname
with open(fname, "w+") as opening:
    start_count_read = opening.read()
    for segea in Segments():
        for funcea in Functions(segea, SegEnd(segea)):
            tif = tinfo_t()
            get_tinfo2(funcea, tif)
            funcdata = func_type_data_t()
            tif.get_func_details(funcdata)
            functionName = GetFunctionName(funcea)
            adr = idaapi.get_fchunk(funcea)
            if funcdata.size() != 0:
                # (address) (number function arguments) 
                info_str = str(funcea) + "\n"
                info_str += str(int(funcdata.size())) + "\n"
                for i in xrange(funcdata.size()):
                    info_str += print_tinfo('', 0, 0, PRTYPE_1LINE, funcdata[i].type, '', '') + "\n"
                start_count_write = opening.write(bytes(info_str))
            if funcdata.size() == 0:
                f = idaapi.get_func(funcea)
                try:
                    cfunc = idaapi.decompile(f)
                except DecompilationFailure:
                    continue
                else:
                    sv = cfunc.get_pseudocode()
    	                # print hex(funcea), " ",functionName
                    for sline in sv:
                        arg = take_arg(idaapi.tag_remove(sline.line))
                        if arg != None:
                            info_str = str(funcea) + "\n"
                            info_str += str(len(arg)) + "\n"
                            for j in xrange(len(arg)):
                                info_str += arg[j] + "\n"
                            start_count_write = opening.write(bytes(info_str))
                        break
                

	                     
