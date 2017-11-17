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

#include "type.h"
#include "mm.h"
#include "cmisc.h"
#include "log.h"

#include "cstring.h"

#include "task.h"

#include "cmpic.inc"

#include "crfs.h"
#include "demo_hsrfs.h"


static CSTRING  *g_rfs_path  = NULL_PTR;
static CSTRING  *g_node_type = NULL_PTR;

static DEMO_HSRFS_ARG g_demo_hsrfs_arg = {CMPI_ANY_TCID, 0, 0, NULL_PTR};


EC_BOOL __test_crfs_runner(CSTRING *crfs_root_dir)
{
    UINT32 crfs_modi;

    crfs_modi = crfs_start(crfs_root_dir);
    ASSERT(ERR_MODULE_ID != crfs_modi);

    /*crfs_end(crfs_modi);*/

    dbg_log(SEC_0137_DEMO, 9)(LOGSTDOUT, "[DEBUG] __test_crfs_runner: crfs_modi = %ld\n", crfs_modi);
 
    return (EC_TRUE);
}

/*parse args for crfs*/
EC_BOOL __test_crfs_parse_args(int argc, char **argv)
{
    int idx;
 
    for(idx = 0; idx < argc; idx ++)
    {
        if(0 == strcasecmp(argv[idx], "-node_type") && idx + 1 < argc)
        {
            g_node_type = cstring_new((UINT8 *)argv[idx + 1], LOC_NONE_BASE);
            ASSERT(NULL_PTR != g_node_type);
            continue;
        }
     
        if(0 == strcasecmp(argv[idx], "-rfs_path") && idx + 1 < argc)
        {
            g_rfs_path = cstring_new((UINT8 *)argv[idx + 1], LOC_NONE_BASE);
            ASSERT(NULL_PTR != g_rfs_path);
            continue;
        }

        if(0 == strcasecmp(argv[idx], "-rfs_tcid") && idx + 1 < argc)
        {
            g_demo_hsrfs_arg.tcid = c_ipv4_to_word(argv[idx + 1]);/*rfs tcid*/
            continue;
        }

        if(0 == strcasecmp(argv[idx], "-rfs_rank") && idx + 1 < argc)
        {
            g_demo_hsrfs_arg.rank = atol(argv[idx + 1]);/*rfs rank*/
            continue;
        }

        if(0 == strcasecmp(argv[idx], "-rfs_modi") && idx + 1 < argc)
        {
            g_demo_hsrfs_arg.modi = atol(argv[idx + 1]);/*rfs rank*/
            continue;
        }

        if(0 == strcasecmp(argv[idx], "-rfs_home_dir") && idx + 1 < argc)
        {
            g_demo_hsrfs_arg.home_dir = c_str_dup(argv[idx + 1]);/*rfs home dir*/
            continue;
        }
    }

     return (EC_FALSE);
}

int main_crfs(int argc, char **argv)
{
    task_brd_default_init(argc, argv);

    if(EC_FALSE == task_brd_default_check_validity())
    {
        dbg_log(SEC_0137_DEMO, 0)(LOGSTDOUT, "error:main_crfs: validity checking failed\n");
        task_brd_default_abort();
        return (-1);
    }

    __test_crfs_parse_args(argc, argv);
 
    if(NULL_PTR != g_node_type)
    {
        if(EC_TRUE == cstring_is_str(g_node_type, (const UINT8 *)"rfs"))
        {
            ASSERT(NULL_PTR != g_rfs_path);
            task_brd_default_add_runner(CMPI_ANY_TCID, CMPI_ANY_RANK, 
                                        (const char *)"__test_crfs_runner", 
                                        (TASK_RUNNER_FUNC)__test_crfs_runner, 
                                        (void *)g_rfs_path);
        }
    }

    /*start the defined runner on current (tcid, rank)*/
    task_brd_default_start_runner();
 
    return (0);
}

int main(int argc, char **argv)
{
    return main_crfs(argc, argv);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

