#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcsignal.h"
#include "pub_tool_libcsetjmp.h" 
#include "pub_tool_libcprint.h"
#include "pub_tool_libcfile.h" //file open
#include "priv_storage.h"
#include "pub_core_threadstate.h"
#include "pub_core_libcsignal.h"
#include "hashmap.c"
#include "hashmap.h"
#include "pub_tool_debuginfo.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_options.h"
#include "pub_tool_machine.h"     // VG_(fnptr_to_fnentry)
#include "pub_tool_xarray.h"   // XArray
#include "aspacemgr-linux.c"


#define KEY_MAX_LENGTH (25)
#define FM_ONLY_SMALL_VAL 0x1
#define FM_POINTER 0x2
#define FM_RWX_POINTER 0x4
#define FM_RW_POINTER 0x8
#define FM_R_POINTER 0x10
#define FM_RX_POINTER 0x20
#define FM_FN_POINTER 0x40
#define FM_ADDR_STACK 0x80
#define FM_ADDR_HEAP 0x100
#define FM_VTABLE 0x200
#define FM_RTTI 0x400

//typedef struct _FeaturesMap{
//    Long value;
//    UInt flag;
//    Bool only_small_values;
//    Bool pointer;
//    Bool rw_pointer;
//    Bool r_pointer;
//    Bool rx_pointer;
//    Bool rwx_pointer;
//    Bool fn_pointer;
//    Bool addr_on_stack;
//    Bool addr_on_heap;//?
//    Bool probably_vtable;
//    Bool rtti_presence;
//
//} FeaturesMap;

typedef struct _ArgContext {
    //Long *values;
    Long number_used_values;
    Long max_number_values; //техническая характеристика
    Long *feature_map;
    Long *values;
} ArgContext;

typedef struct _FuncEvaluateContext
{
    Int arg_number;
    ArgContext *arg_contexts;
} FuncEvaluateContext;

typedef struct _EvaluateContext
{
    Char key_string[KEY_MAX_LENGTH];
    FuncEvaluateContext *func;
} EvaluateContext;


/*------------------------------------------------------------*/
/*--- Command line options                                 ---*/
/*------------------------------------------------------------*/
static const HChar* fname = "ida_arg.txt";
static map_t mymap;
static const HChar* out_file = "lackey_%p.json";
static VgFile* out_fd;

static Bool lk_process_cmd_line_option(const HChar* arg)
{
   if VG_STR_CLO(arg, "--fname", fname) {}
   else return False;
   
   tl_assert(fname);
   tl_assert(fname[0]);
   return True;
}

static void lk_print_usage(void)
{ 
   VG_(printf)("    --fname=<name>           input file <name> \n");
}

static void lk_print_debug_usage(void)
{  
   VG_(printf)("    (none)\n");
}

/*------------------------------------------------------------*/
/*--- Stuff for heuristics                                 ---*/
/*------------------------------------------------------------*/
static Bool pointer_flag = 0;
static Bool rw_pointer_flag = 0;
static Bool r_pointer_flag = 0;
static Bool rx_pointer_flag = 0;
static Bool rwx_pointer_flag = 0;
static Long view_arg = 0;
static Long pointers = 0;
static Long virt_class = 0;
static Long func_pointer = 0;


void record_mapping( Addr value, Addr addr, SizeT len, UInt prot,
                        ULong dev, ULong ino, Off64T offset,
                        const HChar* filename )
{
    if((prot & VKI_PROT_READ) && (prot & VKI_PROT_WRITE) && !ino && !(prot & VKI_PROT_EXEC)) {
        //if our value led in RW section
        if (value > addr && value <= addr + len){
            pointer_flag = True;
            rw_pointer_flag = True;
            pointers++;
        }
    }
    if((prot & VKI_PROT_READ) && (prot & VKI_PROT_WRITE) && !ino && (prot & VKI_PROT_EXEC)) {
        //if our value led in RW section
        if (value > addr && value <= addr + len){
            pointer_flag = True;
            rwx_pointer_flag = True;
            pointers++;
        }
    }
    if((prot & VKI_PROT_READ) && !(prot & VKI_PROT_WRITE) && !ino && !(prot & VKI_PROT_EXEC)) {
        //if our value led in R section
        if (value > addr && value <= addr + len){
            pointer_flag = True;
            r_pointer_flag = True;
            pointers++;
        }
    }
    if((prot & VKI_PROT_READ) && !(prot & VKI_PROT_WRITE) && !ino && (prot & VKI_PROT_EXEC)) {
        //if our value led in RX section
        if (value > addr && value <= addr + len){
            pointer_flag = True;
            rx_pointer_flag = True;
            pointers++;
        }
    }
}

void heuristic_pointer(Long *flag, Long value){
    //smt pointers are NULL
    if (!value)
        return 0;
    pointer_flag = False;
    r_pointer_flag =  False;
    rw_pointer_flag = False;
    rx_pointer_flag = False;
    rwx_pointer_flag = False;
    lk_parse_procselfmaps((Addr)value, &record_mapping, NULL);
    if (pointer_flag)
        *flag |= FM_POINTER;
    if (rw_pointer_flag)
        *flag |= FM_RW_POINTER;
    if (rwx_pointer_flag)
        *flag |= FM_RWX_POINTER;
    if (r_pointer_flag)
        *flag |= FM_R_POINTER;
    if (rx_pointer_flag)
        *flag |= FM_RX_POINTER;
//    arg_context->rw_pointer = rw_pointer_flag;
//    arg_context->r_pointer = r_pointer_flag;
//    arg_context->rx_pointer = rx_pointer_flag;
//    arg_context->rwx_pointer = rwx_pointer_flag;
//    if (pointer_flag)
//        pointers++;
}

void heuristic_stack_heap(Long *flag, Long arg_value){

    const ThreadId thread_id = VG_(get_running_tid)();
    Long stack_hi = VG_(get_ThreadState)(thread_id)->client_stack_highest_byte;
    Long stack_lo = stack_hi - VG_(get_ThreadState)(thread_id)->client_stack_szB;

    if (arg_value <= stack_hi && stack_lo <= arg_value ) {
        *flag |= FM_ADDR_STACK;
        *flag |= FM_POINTER;
        return 0;
    }
//    if (arg_context->feature_map.pointer && !arg_context->feature_map.addr_on_stack){
//        arg_context->feature_map.addr_on_heap = True;
//    }
}

void heuristic_vtable(Long *flag, Long arg_value){
    //smt pointers are NULL
    if(!(*flag & FM_POINTER) || !arg_value){
        return 0;
    }
    Long in_arg_value = *((Long *)arg_value);
    if(in_arg_value < 16){
        return 0;
    }
    
    if (ML_(find_rw_mapping)(in_arg_value - 16, in_arg_value) != NULL){

        /* can take pointer - data placed in read-write segment*/
        Long data_from_rw = *(Long *)(in_arg_value);
        Long data_from_rw8 = *(Long *)(in_arg_value - 8);

        /* rtti locate in read-write segment */
        if (ML_(find_rw_mapping)(data_from_rw8, data_from_rw8) != NULL){
            *flag |= FM_RTTI;
        }
        /* vtable should contain a pointer to the function located in read-execute segment */
        DebugInfo *di = VG_(find_DebugInfo)(VG_(current_DiEpoch)(), data_from_rw);
        if (di == NULL){
            return 0;
        }
        if (ML_(find_rx_mapping)(di, data_from_rw, data_from_rw) != NULL){
            *flag |= FM_VTABLE;
            virt_class++;
        }
    }
}

void heuristic_fn_pointer(Long *flag, Long arg_value){
    if(!(*flag & FM_POINTER) || !arg_value){
        return 0;
    }
    
    Long in_arg_value = *((Long *)arg_value);
    DebugInfo *di = VG_(find_DebugInfo)(VG_(current_DiEpoch)(),in_arg_value);
    if (di == NULL){
        return 0;
    }
    if (ML_(find_rx_mapping)(di, in_arg_value, in_arg_value) != NULL){
        *flag |= FM_FN_POINTER;
        func_pointer++;
    }
}


void arg_evalute_fsm(Long *flag, Long arg_value) {
    heuristic_pointer(flag, arg_value);
    heuristic_stack_heap(flag, arg_value);
    heuristic_vtable(flag, arg_value);
    heuristic_fn_pointer(flag, arg_value);
}


/*------------------------------------------------------------*/
/*--- Stuff for trace-argyments                            ---*/
/*------------------------------------------------------------*/
static Bool clo_trace_sbs = False;
static Long fn_counts = 0;
static Long real_fn_counts = 0;


Long get_arg_value(VexGuestArchState* vex, Int j){
    switch (j+1){
        case 1:
            return vex->guest_RDI;
        case 2:
            return vex->guest_RSI;
        case 3:
            return vex->guest_RDX;
        case 4:
            return vex->guest_RCX;
        case 5:
            return vex->guest_R8;
        case 6:
            return vex->guest_R9;
        default:
            break;
    }
    const ThreadId thread_id = VG_(get_running_tid)();
    Addr current_sp = VG_(get_SP)(thread_id); //stack address
    UInt offset = 8 * (1 + j - 6);
    return *((Long *)current_sp + offset);
}


static void evaluate_function(Addr addr)
{
    DebugInfo *di = VG_(find_DebugInfo)(VG_(current_DiEpoch)() , addr);
    if(di == NULL){
        clo_trace_sbs = False;
        return 0;
    }
    EvaluateContext* evcon;
    Char key_string[KEY_MAX_LENGTH];
    /*we need the loading address of the text section 
    to calculate the address of the function without an offset.*/
    VG_(snprintf)(key_string, KEY_MAX_LENGTH,"%lld", addr - di->text_bias);

    Int error = hashmap_get(mymap, key_string, (void**)(&evcon));
    //not such element
    if (error || evcon->func == NULL){
        clo_trace_sbs = False;
        return 0;
    }
    real_fn_counts++;
    const ThreadId thread_id = VG_(get_running_tid)();
    VexGuestArchState* vex = &(VG_(get_ThreadState)(thread_id)->arch.vex);
    

    Int arg_num = evcon->func->arg_number;
    view_arg += arg_num;
    tl_assert(arg_num != 0);
    ArgContext *argcon = evcon->func->arg_contexts;
    if(argcon == NULL){
        argcon = (ArgContext *)VG_(calloc)("arg.con", arg_num, sizeof(ArgContext));
        tl_assert(argcon != NULL);
        evcon->func->arg_contexts = argcon;
        for(Int i = 0; i < arg_num; i++){
            argcon[i].number_used_values = 0;
            argcon[i].max_number_values = 10;
            //massif of argument features
            argcon[i].feature_map = (Long *) VG_(calloc)("arg.con.feat.map", argcon[i].max_number_values, sizeof(Long));
            tl_assert(argcon[i].feature_map != NULL);
            //massif of argument values
            argcon[i].values = (Long *) VG_(calloc)("arg.con.val", argcon[i].max_number_values, sizeof(Long));
            tl_assert(argcon[i].values != NULL);
        }
    }

    for(Int j = 0; j < arg_num; j++){

        //get argument value from register or stack
        Long arg_value = get_arg_value(vex, j);

        tl_assert(argcon[j].number_used_values < argcon[j].max_number_values);

        Long* argc_feat_map = argcon[j].feature_map;
        Long* argc_values = argcon[j].values;
        argc_feat_map[argcon[j].number_used_values] = 0;
        argc_values[argcon[j].number_used_values]= arg_value;
        argcon[j].number_used_values++;

        if(argcon[j].number_used_values >= argcon[j].max_number_values){
            argc_feat_map = VG_(realloc)("arg.con.feat.map", argc_feat_map, argcon[j].max_number_values * 2 * sizeof(Long));
            argc_values = VG_(realloc)("arg.con.val", argc_values, argcon[j].max_number_values * 2 * sizeof(Long));
            //tl_assert(argc == NULL);
            argcon[j].max_number_values *= 2;
            argcon[j].feature_map = argc_feat_map;
            argcon[j].values = argc_values;
        }
        arg_evalute_fsm(&argc_feat_map[argcon[j].number_used_values], arg_value);
    }
    clo_trace_sbs = False;
}


/*------------------------------------------------------------*/
/*--- Stuff for hash mapping                               ---*/
/*------------------------------------------------------------*/


Int scan_line(Int fd, Char *buf){
    Int current_index = -1;//указывает размер считаной строки
    Int error;
    //находим первый переход строки или обнаруживаем конец файла
    do{ 
        current_index++;
        error = VG_(read)(fd, buf + current_index, 1);
    } while(error > 0 && buf[current_index] != '\n');
    return error;
}


void init_hashmap(map_t mymap){

    Int fd = VG_(fd_open)(fname, VKI_O_RDONLY, 666);

    EvaluateContext* value;
    Char array[100];//буферный массив для считывания построчно всего файла
    Int error = 1;//если 0 - то чтение не произошло
    do{
        //find func address
        error = scan_line(fd, array);
        if (error <= 0)
            break;
        value = (EvaluateContext *)VG_(malloc)("ev.con",sizeof(EvaluateContext));
        VG_(snprintf)(value->key_string, KEY_MAX_LENGTH, "%lld", VG_(strtoll10)(array, NULL));

        //find arg number
        error = scan_line(fd, array);
        if (error <= 0)
            break;
        Int arg_number = VG_(strtoll10)(array, NULL);
        value->func = (FuncEvaluateContext *)VG_(malloc)("fun.ev.con",sizeof(FuncEvaluateContext));
        value->func->arg_number = arg_number;
        value->func->arg_contexts = NULL;

        //return 0 if successful
        error = hashmap_put(mymap, value->key_string, value);
        tl_assert(error == 0);

        fn_counts++;
        /* open, when arguments types from ida become important
        //pass arguments types
        for(Int j = 0; j < arg_number; j++){ 
            error = scan_line(fd, array);
            VG_(printf)("%s\n",array);
            if (error <= 0)
                break;
        }*/
    } while(1);
    VG_(close)(fd);
}

Int post_evaluate(EvaluateContext *item, EvaluateContext *data){

    if (data->func != NULL) {
        VG_(fprintf)(out_fd, "{ \"key\":\"%s\", \"FuncEvaluateContext\":", data->key_string);
        //VG_(printf)("%s  ", data->key_string);

        FuncEvaluateContext *func = data->func;
        if (func == NULL) {
            VG_(fprintf)(out_fd, " 0},\n");
            return 0;
        }
        /*have function contexts*/
        VG_(fprintf)(out_fd, " { \"arg_number\" : %d, \n\"ArgContext\":", func->arg_number);
        ArgContext *arg_con = func->arg_contexts;
        if (arg_con == NULL || arg_con == 0) {
            VG_(fprintf)(out_fd, " 0}},");
            return 0;
        }
        /*have argument contexts*/
        VG_(fprintf)(out_fd, " [ ");
        Int arg_num = func->arg_number;
        for (Int i = 0; i < arg_num; i++){
            if (i !=0 )
                VG_(fprintf)(out_fd, "},");
            VG_(fprintf)(out_fd, "{ \"number_used_values\": %d, \"max_number_values\": %d,",
                arg_con[i].number_used_values, arg_con[i].max_number_values);
            VG_(fprintf)(out_fd, " \"FeaturesMap\" : [");

            for (Int j = 0; j < arg_con[i].number_used_values; j++){
                if (j !=0 )
                    VG_(fprintf)(out_fd, ",");
                VG_(fprintf)(out_fd, "{ \"value\" : %d,", arg_con[i].values[j]);
                VG_(fprintf)(out_fd, " \"only_small_values\" : %d,", arg_con[i].feature_map[j] & FM_ONLY_SMALL_VAL);
                VG_(fprintf)(out_fd, " \"pointer\" : %d,", arg_con[i].feature_map[j] & FM_POINTER);
                VG_(fprintf)(out_fd, " \"rw_pointer\" : %d,", arg_con[i].feature_map[j] & FM_RW_POINTER);
                VG_(fprintf)(out_fd, " \"r_pointer\" : %d,", arg_con[i].feature_map[j] & FM_R_POINTER);
                VG_(fprintf)(out_fd, " \"rx_pointer\" : %d,", arg_con[i].feature_map[j] & FM_RX_POINTER);
                VG_(fprintf)(out_fd, " \"rwx_pointer\" : %d,", arg_con[i].feature_map[j] & FM_RWX_POINTER);
                VG_(fprintf)(out_fd, " \"fn_pointer\" : %d,", arg_con[i].feature_map[j] & FM_FN_POINTER);
                VG_(fprintf)(out_fd, " \"addr_on_stack\" : %d,", arg_con[i].feature_map[j] & FM_ADDR_STACK);
                VG_(fprintf)(out_fd, " \"addr_on_heap\" : %d,", arg_con[i].feature_map[j] & FM_ADDR_HEAP);
                VG_(fprintf)(out_fd, " \"probably_vtable\" : %d,", arg_con[i].feature_map[j] & FM_VTABLE);
                VG_(fprintf)(out_fd, " \"rtti_presence\" : %d}", arg_con[i].feature_map[j] & FM_RTTI);
            }
            VG_(fprintf)(out_fd, "]");

        }
        VG_(fprintf)(out_fd, "}");

        /*close chars of the json string*/
        VG_(fprintf)(out_fd, " ]}},\n");
    }
    return 0;
}

/*------------------------------------------------------------*/
/*--- Basic tool functions                                 ---*/
/*------------------------------------------------------------*/

static void lk_post_clo_init(void)
{
    init_hashmap(mymap);
}

static
IRSB* lk_instrument ( VgCallbackClosure* closure,
                      IRSB* sbIn, 
                      const VexGuestLayout* layout, 
                      const VexGuestExtents* vge,
                      const VexArchInfo* archinfo_host,
                      IRType gWordTy, IRType hWordTy )
{

   //print fn address in runtime
    if (clo_trace_sbs){
        IRDirty*   di;
        Int        i;
        IRSB*      sbOut;
        IRTypeEnv* tyenv = sbIn->tyenv;

        /* Set up SB */
        sbOut = deepCopyIRSBExceptStmts(sbIn);
        i = 0;
        while (i < sbIn->stmts_used && sbIn->stmts[i]->tag != Ist_IMark) {
        addStmtToIRSB( sbOut, sbIn->stmts[i] );
            i++;
        }
        /*get the fnptr to fnentry*/
        di = unsafeIRDirty_0_N(0, "evaluate_function", 
            VG_(fnptr_to_fnentry)( &evaluate_function ),
            mkIRExprVec_1( mkIRExpr_HWord( vge->base[0])));
        addStmtToIRSB( sbOut, IRStmt_Dirty(di) );
      
        for (/*use current i*/; i < sbIn->stmts_used; i++) {
            IRStmt* st = sbIn->stmts[i];
            if (!st || st->tag == Ist_NoOp) continue;
            addStmtToIRSB( sbOut, st );      // Original statement
        }
        return sbOut;
    }

    if (sbIn->jumpkind == Ijk_Call) {
        /* flag - next block is function */
        clo_trace_sbs = True;   
    }        
    return sbIn;
}

static void lk_fini(Int exitcode)
{
    HChar* lackey_out_file = VG_(expand_file_name)("--lackey-file", out_file);
    VG_(printf)("file name - %s\n", lackey_out_file);
    out_fd = VG_(fopen)(lackey_out_file, VKI_O_CREAT|VKI_O_WRONLY|VKI_O_TRUNC,
                   VKI_S_IRUSR|VKI_S_IWUSR|VKI_S_IRGRP|VKI_S_IROTH); //file for rezults 

    Int print_rez = VG_(fprintf)(out_fd, "{ \"EvaluateContext\" : [\n");
    /*save content of all elements in map*/
    hashmap_iterate(mymap, post_evaluate, 0);
    
    /* Now, destroy the map */
    hashmap_free(mymap);
    VG_(printf)("Number of function at input: %10ld\n", fn_counts);
    VG_(printf)("Number of features analyzed: %10ld\n", fn_counts);
    VG_(printf)("Number of arguments viewed:  %10ld\n", view_arg);
    VG_(printf)("-------------------------------------------\n");
    VG_(printf)("Results of analysis:\n");
    VG_(printf)("pointer          %10ld\n", pointers);
    VG_(printf)("function pointer %10ld\n", func_pointer);
    VG_(printf)("virtual class    %10ld\n", virt_class);
    //add void braces to solve json problem with last ',' symbol
    VG_(fprintf)(out_fd, "{}]}");
    VG_(fclose)(out_fd);
}

static void lk_pre_clo_init(void)
{
   VG_(details_name)            ("Arggrind!!!");
   VG_(details_version)         (NULL);
   VG_(details_description)     ("my new Valgrind tool");
   VG_(details_copyright_author)(
      "Copyright (C) 2020-2021, and GNU GPL'd, by Barbara Akhapkina and Mike Voronov");
   VG_(details_bug_reports_to)  (VG_BUGS_TO);
   VG_(details_avg_translation_sizeB) ( 640 );
   
   VG_(clo_vex_control).iropt_unroll_thresh = 0;   // cannot be overridden.
   VG_(clo_vex_control).guest_chase = False;       // cannot be overridden.

   VG_(basic_tool_funcs)          (lk_post_clo_init,
                                   lk_instrument,
                                   lk_fini);

   VG_(needs_command_line_options)(lk_process_cmd_line_option,
                                   lk_print_usage,
                                   lk_print_debug_usage);

    
    mymap = hashmap_new();

}

VG_DETERMINE_INTERFACE_VERSION(lk_pre_clo_init)

/*--------------------------------------------------------------------*/
/*--- end                                                lk_main.c ---*/
/*--------------------------------------------------------------------*/
 
