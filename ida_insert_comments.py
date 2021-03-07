# from idautils import *
# from idaapi import *
import json

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

#fname = "/home/stone-pardon/lackey_21644.json" 
idc.AskStr(".txt", "Enter a full path file name")
if fname == None:
    print "Defalt file name is ida_for_pro.txt"
    fname = "ida_arg.txt"
else:
	print fname
with open(fname, "r+") as opening:
    print "I can read!"
    arggrind = json.load(opening)
    evalcon = arggrind["EvaluateContext"]
    for elem in evalcon:
        if elem:
            print int(elem["key"])
            funccon = elem["FuncEvaluateContext"]
            if funccon["ArgContext"] == 0 :
                print "No info"
                continue
            print "Have info"
            argument_num = 1
            comment = []
            for content in funccon["ArgContext"]:
                featmap = content["FeaturesMap"]
                buf = "arg_num "
                buf += str(argument_num)
                buf += " Features:"
                if featmap["only_small_values"] :
                    buf += " only_small_values"
                if featmap["pointer"] :
                    buf += " pointer"
                if featmap["fn_pointer"] :
                    buf += " fn_pointer"
                if featmap["addr_on_stack"] :
                    buf += " addr_on_stack"
                if featmap["addr_on_heap"] :
                    buf += " addr_on_heap"
                if featmap["probably_vtable"] :
                    buf += " probably_vtable"
                if featmap["rtti_presence"] :
                    buf += " rtti_presence"
                if content["number_used_values"] :
                    buf += "; values of arg"
                    for value in content["values"] :
                        buf += ' ' + str(value)
                argument_num += 1
                comment.append(buf)
            print comment
            function_comment = GetFunctionCmt(int(elem["key"]), 0)
            if function_comment:
                comment.append(function_comment)
            # comment.append("\n*********I was here**********")
            SetFunctionCmt(int(elem["key"]), '\n'.join(comment), 0)
