from idautils import *
from idaapi import *



def take_arg(str_input):
    arg = []
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
        reg = data.reg1()
        rez = "reg1 "
        rez += str(reg)
        rez += " offset " + str(data.regoff())
        return rez

print "Hello? world!"
for segea in Segments():
    for funcea in Functions(segea, SegEnd(segea)):
        tif = tinfo_t()
        get_tinfo2(funcea, tif)
        funcdata = func_type_data_t()
        tif.get_func_details(funcdata)
        functionName = GetFunctionName(funcea)
        adr = idaapi.get_fchunk(funcea)
        if funcdata.size() != 0:
            print hex(funcea), " ",hex(funcdata.cc), " ", funcdata.stkargs, " ", functionName
            for i in xrange(funcdata.size()):
                # 0 none 
                # 1 stack offset
                # 2 distributed (scattered)
                # 3 one register (and offset within it)
                # 4 register pair
                # 5 register relative
                # 6 global address
                # 7 custom argloc (7 or higher)
                print "    Arg %d: %s %s location %s" % (i, print_tinfo('', 0, 0, PRTYPE_1LINE, funcdata[i].type, '', ''), 
                    funcdata[i].name, argloc_info(funcdata[i].argloc))
        if funcdata.size() == 0:
            flag = 1
            f = idaapi.get_func(funcea)
            try:
                cfunc = idaapi.decompile(f)
            except DecompilationFailure:
                continue
            else:
                sv = cfunc.get_pseudocode()
                print hex(funcea), " ",functionName
                for sline in sv:
                    print "    !!Arg %s" % (take_arg(idaapi.tag_remove(sline.line)))
                    break 

                    