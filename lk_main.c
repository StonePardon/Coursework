#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_debuginfo.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_options.h"
#include "pub_tool_machine.h"     // VG_(fnptr_to_fnentry)



/*------------------------------------------------------------*/
/*--- Stuff for --basic-counts                             ---*/
/*------------------------------------------------------------*/

/* Nb: use ULongs because the numbers can get very big */
static ULong n_func_calls    = 0;
static ULong n_guest_instrs  = 0;

static void add_one_func_call(void)
{
   n_func_calls++;
}

static void add_one_guest_instr(void)
{
   n_guest_instrs++;
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
   IRDirty*   di;
   Int        i;
   IRSB*      sbOut;
   IRTypeEnv* tyenv = sbIn->tyenv;
   Addr       iaddr = 0, dst;
   UInt       ilen = 0;
   Bool       condition_inverted = False;
   DiEpoch    ep = VG_(current_DiEpoch)();

   if (gWordTy != hWordTy) {
      /* We don't currently support this case. */
      VG_(tool_panic)("host/guest word size mismatch");
   }

   /* Set up SB */
   sbOut = deepCopyIRSBExceptStmts(sbIn);

   // Copy verbatim any IR preamble preceding the first IMark
   i = 0;
   while (i < sbIn->stmts_used && sbIn->stmts[i]->tag != Ist_IMark) {
      addStmtToIRSB( sbOut, sbIn->stmts[i] );
      i++;
   }
   
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
         case Ist_StoreG: 
         case Ist_LoadG:
         case Ist_Dirty:
         case Ist_CAS: 
         case Ist_LLSC: 
            addStmtToIRSB( sbOut, st ); 
            break;
         case Ist_Exit:{

            Bool guest_exit, inverted;
            guest_exit = (st->Ist.Exit.jk == Ijk_Boring) ||
                         (st->Ist.Exit.jk == Ijk_Call) ||
                         (st->Ist.Exit.jk == Ijk_Ret);

            if (guest_exit) {
                /* Stuff to widen the guard expression to a host word, so
                   we can pass it to the branch predictor simulation
                   functions easily. */
                IRType   tyW    = hWordTy;
                IROp     widen  = tyW==Ity_I32  ? Iop_1Uto32  : Iop_1Uto64;
                IROp     opXOR  = tyW==Ity_I32  ? Iop_Xor32   : Iop_Xor64;
                IRTemp   guard1 = newIRTemp(sbOut->tyenv, Ity_I1);
                IRTemp   guardW = newIRTemp(sbOut->tyenv, tyW);
                IRTemp   guard  = newIRTemp(sbOut->tyenv, tyW);
                IRExpr*  one    = tyW==Ity_I32 ? IRExpr_Const(IRConst_U32(1))
                                               : IRExpr_Const(IRConst_U64(1));

                /* Widen the guard expression. */
                addStmtToIRSB( sbOut,
                               IRStmt_WrTmp( guard1, st->Ist.Exit.guard ));
                addStmtToIRSB( sbOut,
                               IRStmt_WrTmp( guardW,
                                             IRExpr_Unop(widen,
                                                         IRExpr_RdTmp(guard1))) );
                /* If the exit is inverted, invert the sense of the guard. */
                addStmtToIRSB(sbOut,
                        IRStmt_WrTmp(
                                guard,
                                inverted ? IRExpr_Binop(opXOR, IRExpr_RdTmp(guardW), one)
                                    : IRExpr_RdTmp(guardW)
                                    ));
            }
            if(st->Ist.Exit.jk == Ijk_Call){
                //IRConst*   dst = st->Ist.Exit.dst;
                VG_(printf)("Ijk_Call \n");
            }
            if(st->Ist.Exit.jk == Ijk_Ret){
                //IRConst*   dst = st->Ist.Exit.dst;
                VG_(printf)("Ijk_Ret \n");
            }
            if(st->Ist.Exit.jk == Ijk_INVALID){
                //IRConst*   dst = st->Ist.Exit.dst;
                VG_(printf)("Ijk_INVALID \n");
            }
            if(st->Ist.Exit.jk == Ijk_NoDecode){
                //IRConst*   dst = st->Ist.Exit.dst;
                VG_(printf)("Ijk_NoDecode \n");
            }
//             if(st->Ist.Exit.jk == Ijk_Boring){
//                 IRConst*   dst = st->Ist.Exit.dst;
//                 VG_(printf)("Ijk_Boring \n");
//             }
             
            addStmtToIRSB( sbOut, st );
            break;
         }
         default:
            ppIRStmt(st);
            tl_assert(0);
      }
   }
   return sbOut;
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

   /*VG_(needs_command_line_options)(lk_process_cmd_line_option,
                                   lk_print_usage,
                                   lk_print_debug_usage);*/
}

VG_DETERMINE_INTERFACE_VERSION(lk_pre_clo_init)

/*--------------------------------------------------------------------*/
/*--- end                                                lk_main.c ---*/
/*--------------------------------------------------------------------*/
 
