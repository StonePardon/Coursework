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
//#include "pub_core_mallocfree.h"
#include "pub_tool_debuginfo.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_options.h"
#include "pub_tool_machine.h"     // VG_(fnptr_to_fnentry)
#include "pub_tool_xarray.h"   // XArray

#define KEY_MAX_LENGTH (25)

typedef struct _FeaturesMap{
    Long minval;
    Long maxval;
    Long expected;
    Bool only_small_values;
    Bool pointer;
    Bool fn_pointer;
    Bool addr_on_stack;
    Bool addr_on_heap;
    Bool probably_vtable;
    Bool rtti_presence;
} FeaturesMap;

typedef struct _ArgContext {
    Long *values;
    Long number_used_values;
    Long max_number_values;
    FeaturesMap feature_map;
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
static Bool pointer_flag = False;
static Long fn_counts = 0;
//static VG_MINIMAL_JMP_BUF(myjmpbuf);


static void SIGSEGV_handler(Int signum)
{
    VG_(printf)("I catch a signal!!!\n");
    //VG_MINIMAL_LONGJMP(myjmpbuf);
    //pointer_flag = False;
}

void heuristic_pointer(ArgContext *arg_context, Long value){
    vki_sigaction_toK_t sigsegv_new;
    vki_sigaction_fromK_t sigsegv_saved;

    Int res;
    /* Install own SIGSEGV handler */
    sigsegv_new.ksa_handler  = &SIGSEGV_handler;
    //((void(*)(Int)) sigsegv_new.ksa_handler) (1);
    sigsegv_new.sa_flags    = 0;
    sigsegv_new.sa_restorer = NULL;

    res = VG_(sigemptyset)( &sigsegv_new.sa_mask);
    tl_assert(res == 0);

    res = VG_(sigaction)( VKI_SIGSEGV, &sigsegv_new, NULL);
    tl_assert(res == 0);

    /*сама проверка*/
   //if (VG_MINIMAL_SETJMP(myjmpbuf) == 0) {
    VG_(printf)("try to take pointer - %10llx\n", value);
        Long new = *((long *) value);
        //VG_(printf)("pointer %llx\n", new);
        //Long neww = new;
        //return True;
   //} else
        //VG_(printf)("Its not a pointer\n");
        //return False;
}

void heuristic_stack_heap(ArgContext *arg_context, Long arg_value){

    const ThreadId thread_id = VG_(get_running_tid)();
    Long stack_hi = VG_(get_ThreadState)(thread_id)->client_stack_highest_byte;
    Long stack_lo = stack_hi - VG_(get_ThreadState)(thread_id)->client_stack_szB;

    if (arg_value <= stack_hi && stack_lo <= arg_value ) {
        arg_context->feature_map.addr_on_stack = True;
        arg_context->feature_map.pointer = True;
        //VG_(printf)("On stack %llx\n", arg_value);
        return 0;
    }
    if (arg_context->feature_map.pointer && !arg_context->feature_map.addr_on_stack)
        arg_context->feature_map.addr_on_heap = True; 
}

void heuristic_vtable(ArgContext *arg_context, Long arg_value){
    if(!arg_context->feature_map.pointer){
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
            arg_context->feature_map.rtti_presence = True;
        }
        /* vtable should contain a pointer to the function located in read-execute segment */
        DebugInfo *di = VG_(find_DebugInfo)(VG_(current_DiEpoch)(), data_from_rw);
        if (di == NULL){
            return 0;
        }
        if (ML_(find_rx_mapping)(di, data_from_rw, data_from_rw) != NULL){
            arg_context->feature_map.probably_vtable = True;
        }
    }
}

void heuristic_fn_pointer(ArgContext *arg_context, Long arg_value){
        if(!arg_context->feature_map.pointer){
        return 0;
    }

    Long in_arg_value = *((Long *)arg_value);
    DebugInfo *di = VG_(find_DebugInfo)(VG_(current_DiEpoch)(),in_arg_value);
    if (di == NULL){
        return 0;
    }
    if (ML_(find_rx_mapping)(di, in_arg_value, in_arg_value) != NULL){
        arg_context->feature_map.fn_pointer = True;
    }
}


void arg_evalute_fsm(ArgContext *arg_context, Long arg_value) {
    heuristic_pointer(arg_context, arg_value);
    heuristic_stack_heap(arg_context, arg_value);
    heuristic_vtable(arg_context, arg_value);
    heuristic_fn_pointer(arg_context, arg_value);
}



/*------------------------------------------------------------*/
/*--- Stuff for trace-argyments                            ---*/
/*------------------------------------------------------------*/
static Bool clo_trace_sbs = False;


Long get_arg_value(VexGuestArchState* vex, Int j){
    switch (j+1){
        case 1:
            return vex->guest_RDI;
        case 2:
            return vex->guest_RSI;
        case 3:
            return vex->guest_RCX;
        case 4:
            return vex->guest_RDX;
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

    const ThreadId thread_id = VG_(get_running_tid)();
    VexGuestArchState* vex = &(VG_(get_ThreadState)(thread_id)->arch.vex);
    

    Int arg_num = evcon->func->arg_number;
    tl_assert(arg_num != 0);
    ArgContext *argcon = evcon->func->arg_contexts;
    if(argcon == NULL){
        argcon = (ArgContext *)VG_(calloc)("arg.con", arg_num, sizeof(ArgContext));
        for(Int i = 0; i < arg_num; i++){
            argcon[i].number_used_values = 0;
            argcon[i].max_number_values = 10;
            argcon[i].values = (Long *) VG_(calloc)("arg.con.val", argcon[i].max_number_values, sizeof(Long));
            tl_assert(argcon[i].values != NULL);

            argcon[i].feature_map.only_small_values = False;
            argcon[i].feature_map.pointer = False;
            argcon[i].feature_map.fn_pointer = False;
            argcon[i].feature_map.addr_on_stack = False;
            argcon[i].feature_map.addr_on_heap = False;
            argcon[i].feature_map.probably_vtable = False;
            argcon[i].feature_map.rtti_presence = False;
        }
    }

    for(Int j = 0; j < arg_num; j++){
        //get argument value from register or stack
        Long arg_value = get_arg_value(vex, j);

        tl_assert(argcon[j].number_used_values < argcon[j].max_number_values);

        Long* argc = argcon[j].values;
        argc[argcon[j].number_used_values] = arg_value;
        argcon[j].number_used_values++;

        if(argcon[j].number_used_values >= argcon[j].max_number_values){
            argc = VG_(realloc)("arg.con.val", argc, argcon[j].max_number_values * 2 * sizeof(Long));
            argcon[j].max_number_values *= 2;
            argcon[j].values = argc;
        }

        arg_evalute_fsm(&argcon[j], arg_value); 
    }
    clo_trace_sbs = False;
}


/*------------------------------------------------------------*/
/*--- Stuff for hashmapping                                ---*/
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
    tl_assert(fd != NULL);

    EvaluateContext* value;
    Char array[50];//буферный массив для считывания построчно всего файла
    Int error = 1;//если 0 - то чтение не произошло
    do{
        //find func address
        error = scan_line(fd, array);
        if (error <= 0)
            break;
        value = (EvaluateContext *)VG_(malloc)("ev.con",sizeof(EvaluateContext));
        VG_(snprintf)(value->key_string, KEY_MAX_LENGTH, "%lld", VG_(strtoll10)(array, NULL));

        //find nuber of arguments
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
        
        for(Int j = 0; j < arg_number; j++){
            error = scan_line(fd, array);
            if (error <= 0)
                break;
        }
    } while(1);

    VG_(close)(fd);
}

/*------------------------------------------------------------*/
/*--- Basic tool functions                                 ---*/
/*------------------------------------------------------------*/

static void lk_post_clo_init(void)
{
  
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
     VG_(printf)("    I finish? Wow!\n");
     // for (index=0; index<fn_counts; index+=1)
     // {
     //     snprintf(key_string, KEY_MAX_LENGTH, "%s%d", KEY_PREFIX, index);

     //     error = hashmap_get(mymap, key_string, (void**)(&value));
     //     printf(" %d ", error==MAP_OK);
     //     assert(error==MAP_OK);

     //     error = hashmap_remove(mymap, key_string);
     //     printf(" %d \n", error==MAP_OK);
     //     assert(error==MAP_OK);

     //     free(value);        
     // }
     
     /* Now, destroy the map */
     hashmap_free(mymap);
}

static void lk_pre_clo_init(void)
{
   VG_(details_name)            ("Arggrind");
   VG_(details_version)         (NULL);
   VG_(details_description)     ("my new Valgrind tool");
   VG_(details_copyright_author)(
      "Copyright (C) 2020, and GNU GPL'd, by Barbara Akhapkina and Michael Voronov");
   VG_(details_bug_reports_to)  (VG_BUGS_TO);
   VG_(details_avg_translation_sizeB) ( 200 );
   
   VG_(clo_vex_control).iropt_unroll_thresh = 0;   // cannot be overridden.
   VG_(clo_vex_control).guest_chase = False;       // cannot be overridden.

   VG_(basic_tool_funcs)          (lk_post_clo_init,
                                   lk_instrument,
                                   lk_fini);

   VG_(needs_command_line_options)(lk_process_cmd_line_option,
                                   lk_print_usage,
                                   lk_print_debug_usage);

    
    mymap = hashmap_new();
    init_hashmap(mymap);
    //hashmap_free(mymap);

}

VG_DETERMINE_INTERFACE_VERSION(lk_pre_clo_init)

/*--------------------------------------------------------------------*/
/*--- end                                                lk_main.c ---*/
/*--------------------------------------------------------------------*/
 