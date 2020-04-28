#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_debuginfo.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_options.h"
#include "pub_tool_machine.h"     // VG_(fnptr_to_fnentry)



/*------------------------------------------------------------*/
/*--- Stuff for basic-counts                               ---*/
/*------------------------------------------------------------*/



/*------------------------------------------------------------*/
/*--- Stuff for trace-superblocks                          ---*/
/*------------------------------------------------------------*/
static Bool clo_trace_sbs = False;

static void trace_superblock(Addr addr)
{
   VG_(printf)("Call jump in the address - 0x%lx\n", addr);
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
//          if (sbIn->next->tag == 6403) {
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

}

VG_DETERMINE_INTERFACE_VERSION(lk_pre_clo_init)

/*--------------------------------------------------------------------*/
/*--- end                                                lk_main.c ---*/
/*--------------------------------------------------------------------*/
 
