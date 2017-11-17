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

#ifndef _DEMO_HSRFS_H
#define _DEMO_HSRFS_H

#include "type.h"

typedef struct
{
    UINT32 tcid;
    UINT32 rank;
    UINT32 modi;
    
    const char *home_dir;
}DEMO_HSRFS_ARG;

#endif /*_DEMO_HSRFS_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

