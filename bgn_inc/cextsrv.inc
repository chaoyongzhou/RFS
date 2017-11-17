/******************************************************************************
*
* Copyright (C) Chaoyong Zhou
* Email: bgnvendor@163.com 
* QQ: 2796796 
*
*******************************************************************************/
#ifdef __cplusplus
extern "C"{
#endif/*__cplusplus*/

#ifndef _CEXTSRV_INC
#define _CEXTSRV_INC

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cmutex.h"
#include "cmisc.h"

#include "csocket.inc"
#include "task.inc"

typedef struct
{
    CSOCKET_CNODE *csocket_cnode;
}CEXTCLNT;

#define CEXTCLNT_CSOCKET_CNODE(cextclnt)       ((cextclnt)->csocket_cnode)

typedef struct
{
    CSOCKET_CNODE *csocket_cnode;
    UINT32         md_id;

    CMUTEX         cmutex;

}CEXTSRV;

#define CEXTSRV_CSOCKET_CNODE(cextsrv)        ((cextsrv)->csocket_cnode)
#define CEXTSRV_MD_ID(cextsrv)                ((cextsrv)->md_id)
#define CEXTSRV_CMUTEX(cextsrv)               (&((cextsrv)->cmutex))

#define CEXTSRV_CMUTEX_INIT(cextsrv, location)          (cmutex_init(CEXTSRV_CMUTEX(cextsrv), CMUTEX_PROCESS_PRIVATE, location))
#define CEXTSRV_CMUTEX_LOCK(cextsrv, location)          (cmutex_lock(CEXTSRV_CMUTEX(cextsrv), location))
#define CEXTSRV_CMUTEX_UNLOCK(cextsrv, location)        (cmutex_unlock(CEXTSRV_CMUTEX(cextsrv), location))
#define CEXTSRV_CMUTEX_CLEAN(cextsrv, location)         (cmutex_clean(CEXTSRV_CMUTEX(cextsrv), location))


#endif/*_CEXTSRV_INC*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
