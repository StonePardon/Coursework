#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcsignal.h"
#include "pub_tool_libcsetjmp.h" 
#include "pub_tool_libcprint.h"
#include "pub_tool_libcfile.h" //file open
#include "priv_storage.h"
#include "pub_core_threadstate.h"
//#include "pub_core_mallocfree.h"
#include "pub_tool_debuginfo.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_options.h"
#include "pub_tool_machine.h"     // VG_(fnptr_to_fnentry)
#include "pub_tool_xarray.h"   // XArray


/*------------------------------------------------------------*/
/*--- Command line options                                 ---*/
/*------------------------------------------------------------*/
static const HChar* fname = "ida_arg.txt";

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
/*--- Stuff for basic-counts                               ---*/
/*------------------------------------------------------------*/
Long offset_stack = 1081344;
//static Bool reg_flag =  False; //flag to test pointer


/*------------------------------------------------------------*/
/*--- Stuff for trace-superblocks                          ---*/
/*------------------------------------------------------------*/
static Bool clo_trace_sbs = False;
static VG_MINIMAL_JMP_BUF(myjmpbuf);

static
void SIGSEGV_handler(int signum)
{

    VG_MINIMAL_LONGJMP(myjmpbuf);
}


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

/*находим нужный адрес в файлеб скомпилированным из иды*/
Int search_addr_in_file(Int fd, Addr addr){
    Char array[50];//буферный массив для считывания построчно всего файла
    Int error = 1;//если 0 - то чтение не произошло
    do{
        //находим первый адрес функции
        error = scan_line(fd, array);
        if (error <= 0)
            break;
        if(VG_(strtoll10)(array, NULL) == (addr - offset_stack)){
            /*Успех*/
            return 1;
        }
        /*если адрес не тот, то мы пропускаем все строки с аргументами*/
        //находим количество аргументов
        error = scan_line(fd, array);
        if (error <= 0)
            break;
        Int arg_number = VG_(strtoll10)(array, NULL);
        //пропускаем строки с ненужными нам аргументами
        for(Int j = 0; j < arg_number; j++){
            error = scan_line(fd, array);
            if (error <= 0)
                break;
        }
    }while(1);
    return 0;
}

static void trace_superblock(Addr addr)
{
    const ThreadId thread_id = VG_(get_running_tid)();
    VexGuestArchState* vex = &(VG_(get_ThreadState)(thread_id)->arch.vex);
    Addr current_sp = VG_(get_SP)(thread_id); //stack address
    Int fd = VG_(fd_open)(fname, VKI_O_RDONLY, 666);
    if(addr == 0x1092a9 && search_addr_in_file(fd, addr) ){
        // VG_(printf)("valgrind_stack_base %lx\n", VG_(get_ThreadState)(thread_id)->os_state.valgrind_stack_base);
        // VG_(printf)("valgrind_stack_init_SP %lx\n", VG_(get_ThreadState)(thread_id)->os_state.valgrind_stack_init_SP);
        // VG_(printf)("client_stack_highest_byte %lx\n", VG_(get_ThreadState)(thread_id)->client_stack_highest_byte); 
        VG_(printf)("Sucsess! addr %lx\n", addr);
        Char buf[5];
        scan_line(fd, buf);
        Int arg_num = VG_(strtoll10)(buf, NULL);
        for(Int j = 0; j < arg_num; j++){
            char arg[50];
            Long arg_value;
            scan_line(fd, arg);
            switch (j+1){
                case 1:
                    VG_(printf)("%s - 0x%llx\n", arg, vex->guest_RDI);
                    arg_value = vex->guest_RDI;
                    // XArray*  blocks = VG_(di_get_stack_blocks_at_ip)( vex->guest_RDI, 0);//take array of StackBlock
                    // if (blocks!= NULL ) {

                    // XArray *x = VG_(newXA)( VG_(malloc), "addr.descr1",
                    // VG_(free), sizeof(HChar) );
                    // XArray *y = VG_(newXA)( VG_(malloc), "addr.descr2",
                    // VG_(free), sizeof(HChar) );
                    // if(VG_(get_data_description)(x,y, VG_(current_DiEpoch)(), vex->guest_RDI)){
                    //      VG_(printf)("!! %s %s\n", x, y);
                    // }
                    break;
                case 2:
                    VG_(printf)("%s - 0x%llx\n", arg, vex->guest_RSI);
                    arg_value = vex->guest_RSI;
                    break;
                case 3:
                    VG_(printf)("%s - 0x%llx\n", arg, vex->guest_RCX);
                    arg_value = vex->guest_RCX;
                    break;
                case 4:
                    VG_(printf)("%s - 0x%llx\n", arg, vex->guest_RDX);
                    arg_value = vex->guest_RDX;
                    break;
                case 5:
                    VG_(printf)("%s - 0x%llx\n", arg, vex->guest_R8);
                    arg_value = vex->guest_R8;
                    break;
                case 6:
                    VG_(printf)("%s - 0x%llx\n", arg, vex->guest_R9);
                    arg_value = vex->guest_R9;
                    break;
                default:
                    break;
            }
            //проверка на указатель - если значение можно разименовать, то перед нами указатель
            //ограничение на значение указателя - он не может быть меньше 1000000
            if (arg_value & 0x1fff000000){
                /*обработчик сигналов при неверном разименовании, чтобы програма продолжала работать*/
                vki_sigaction_toK_t sigsegv_new;
                vki_sigaction_fromK_t sigsegv_saved;

                Int res;
                /* Install own SIGSEGV handler */
                sigsegv_new.ksa_handler  = SIGSEGV_handler;
                sigsegv_new.sa_flags    = 0;
                sigsegv_new.sa_restorer = NULL;

                res = VG_(sigemptyset)( &sigsegv_new.sa_mask);
                tl_assert(res == 0);

                res = VG_(sigaction)( VKI_SIGSEGV, &sigsegv_new, &sigsegv_saved);
                tl_assert(res == 0);
                Int in_reg_value = -1;
                /*сама проверка*/
                if (VG_MINIMAL_SETJMP(myjmpbuf) == 0) {
                    in_reg_value = *((int *)(arg_value));
                    VG_(printf)("pointer %lx - %lx \n", arg_value, in_reg_value);
                    VG_(printf)("-16  %lx\n", *((int *)(in_reg_value - 16)));
                    VG_(printf)("-8   %lx\n", *((int *)(in_reg_value - 8)));
                    VG_(printf)("0    %lx\n\n", *((int *)(in_reg_value )));

                    DebugInfo *di = VG_(find_DebugInfo)(VG_(current_DiEpoch)() , *((int *)(in_reg_value)) );
                    
                    while (di != NULL){
                    
                        for (UInt i = 0; i < VG_(sizeXA)(di->fsm.maps); i++) {
                           DebugInfoMapping* map = VG_(indexXA)(di->fsm.maps, i);
                           VG_(printf)("mapping %18lx - %18lx\n", map->avma, map->avma + map->size);
                           VG_(printf)("rx - %d  rw - %d  ro - %d\n",map->rx, map->rw, map->ro);
                           // if (   map->rx && map->size > 0
                           //     && lo >= map->avma && hi < map->avma + map->size) {
                           //    di->last_rx_map = map;
                           //    return map;
                           // }
                        }
                        di = di->next;
                    }

                    // if ( di != NULL){G_(printf)("mapping %18lx - %18lx, \n")
                    //     VG_(printf)("New version!\nI have debuginfo!!!\n");
                    //     VG_(printf)("%s\n",VG_(DebugInfo_get_soname)( di ));
                    //     VG_(printf)("%s\n",VG_(DebugInfo_get_filename)( di ));
                    //     //VG_(printf)("%d\n",VG_(DebugInfo_get_Mapping_rx)( di ));
                    //     //VG_(printf)("Addr avma %lx\n",VG_(DebugInfo_get_Mapping_avma)( di));
                    //     // UInt linenum;
                    //     // if(VG_(get_linenum)( VG_(current_DiEpoch)(), addr, &linenum)){
                    //     //     VG_(printf)("linenum %lx = %lx\n",addr, linenum );
                    //     // }

                    //     VG_(printf)("text addr - %lx size - %lx\n", VG_(DebugInfo_get_text_avma)(di), VG_(DebugInfo_get_text_size)(di));
                    //     // VG_(printf)("got addr - %lx size - %lx\n", VG_(DebugInfo_get_got_avma)(di), VG_(DebugInfo_get_got_size)(di));
                    //     VG_(printf)("got addr - %lx \n", VG_(DebugInfo_get_got_avma)(di));
                    //     VG_(printf)("gotplt addr - %lx \n", VG_(DebugInfo_get_gotplt_avma)(di));
                    //     VG_(printf)("plt addr - %lx \n", VG_(DebugInfo_get_plt_avma)(di));
                    //     // VG_(printf)("data addr - %lx\n", VG_(DebugInfo_get_data_avma)(di));
                    //     // VG_(printf)("sdata addr - %lx\n", VG_(DebugInfo_get_sdata_avma)(di));
                    //     // VG_(printf)("rodata addr - %lx, size - %lx\n", VG_(DebugInfo_get_rodata_avma)(di), VG_(DebugInfo_get_rodata_size)(di));
                    //     DebugInfoMapping* deb_map_info = ML_(find_rx_mapping)( di, *((int *)(in_reg_value)), *((int *)(in_reg_value)));
                    //     if(deb_map_info != NULL){
                    //         VG_(printf)("I look in mapping!!!\n %lx - addr \n", deb_map_info->avma);
                    //     }                        
                    // }
                    
                }
                
            }
        }
    }
    VG_(close)(fd);
//         XArray*  blocks = VG_(di_get_stack_blocks_at_ip)( current_sp, 0);//take array of StackBlock
//         if (blocks!= NULL && VG_(sizeXA)(blocks) != 0) {
//             VG_(printf)("stack %lx - %lx \n", addr, current_sp);
//         }
       // VG_(printf)("%lx - %lx \n", addr, current_sp);
    clo_trace_sbs = False;
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
        di = unsafeIRDirty_0_N(0, "trace_superblock", 
            VG_(fnptr_to_fnentry)( &trace_superblock ),
            mkIRExprVec_1( mkIRExpr_HWord( vge->base[0])));
        addStmtToIRSB( sbOut, IRStmt_Dirty(di) );

        // XArray *x = VG_(newXA)( VG_(malloc), "addr.descr1",
        // VG_(free), sizeof(HChar) );
        // XArray *y = VG_(newXA)( VG_(malloc), "addr.descr2",
        // VG_(free), sizeof(HChar) );
        // Addr aaa = 0x1fff0004e0;
        // if(VG_(get_data_description)(x,y, VG_(current_DiEpoch)(), aaa)){
        //      VG_(printf)("!! %s %s\n", x, y);
        // }       
        
        for (/*use current i*/; i < sbIn->stmts_used; i++) {
            IRStmt* st = sbIn->stmts[i];
            if (!st || st->tag == Ist_NoOp) continue;
      
            switch (st->tag) {
                case Ist_NoOp:
                case Ist_AbiHint:
                case Ist_Put:
                case Ist_PutI:
                case Ist_MBE:
                case Ist_IMark:
                case Ist_WrTmp:
                case Ist_Store: 
                case Ist_LoadG: 
                case Ist_Dirty: 
                case Ist_CAS: 
                case Ist_LLSC: 
                case Ist_Exit:
                    addStmtToIRSB( sbOut, st );      // Original statement
                    break;

                default:
                    ppIRStmt(st);
                    tl_assert(0);
            }
        }
        return sbOut;
    }

    if(sbIn->jumpkind == Ijk_Call) {
        /* Print this superblock's address. */
            clo_trace_sbs = True;           
//         }
//         else {
//             VG_(printf)("Call jump in the address - ");
//             ppIRExpr(sbIn->next);
//             VG_(printf)("\n");
//             VG_(printf)("\n");
//         }
    }
    return sbIn;
}

static void lk_fini(Int exitcode)
{
}

static void lk_pre_clo_init(void)
{
   VG_(details_name)            ("Arggrind");
   VG_(details_version)         (NULL);
   VG_(details_description)     ("my new Valgrind tool");
   VG_(details_copyright_author)(
      "Copyright (C) 2020, and GNU GPL'd, by SECSEM.");
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

}

VG_DETERMINE_INTERFACE_VERSION(lk_pre_clo_init)

/*--------------------------------------------------------------------*/
/*--- end                                                lk_main.c ---*/
/*--------------------------------------------------------------------*/
 
