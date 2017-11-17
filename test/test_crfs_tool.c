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
#include "log.h"

#include "clist.h"

#include "cmisc.h"
#include "ccode.h"

#include "cbc.h"

#include "task.h"

#include "crfs.h"


void init()
{
    TASK_BRD *task_brd;
  
    init_host_endian();
    cmisc_init(LOC_TASK_0100);

    log_start();

    init_static_mem();

    task_brd = task_brd_default_new();

    task_brd_init(task_brd, NULL_PTR, NULL_PTR, NULL_PTR, NULL_PTR, NULL_PTR); 

    cbc_new(MD_END); /*set the max number of supported modules*/
    cbc_md_reg(MD_CRFS, 1);

    return;
}

void deinit()
{
    task_brd_free(task_brd_default_get());
    cbc_free();
    return;
}

static EC_BOOL __crfs_test_check_str_in(const char *string, const char *tags_str)
{
    return c_str_is_in(string, ":", tags_str);
}

#define __crfs_test_no_md_continue(__crfs_md_id) \
    if(ERR_MODULE_ID == (__crfs_md_id)) {\
        sys_log(LOGCONSOLE, "error: no crfs module, pls open or create it at first\n");\
        continue;\
    }

void set_log_level(UINT32 loglevel)
{
    extern UINT32 g_log_level[ SEC_NONE_END ];
  
    log_level_tab_set_all(g_log_level, SEC_NONE_END, loglevel);
    return;
}

void print_log_level()
{
    extern UINT32 g_log_level[ SEC_NONE_END ];
  
    log_level_tab_print(LOGCONSOLE, g_log_level, SEC_NONE_END);
    return;
}

int __crfs_test_suite_0(int argc, char **argv)
{
    char  cmd_line[1024];
    int   cmd_line_len = sizeof(cmd_line)/sizeof(cmd_line[0]);

    char *cmd_his_tbl[128];
    int   cmd_his_max = sizeof(cmd_his_tbl)/sizeof(cmd_his_tbl[0]);
    int   cmd_his_size = 0;

    int   idx;

    CSTRING *crfs_root_dir;

    const char *usage[] = {
        "open rfs <root dir>           # e.g. open rfs /data/cache/rnode1",
        "close rfs",
        "create np <model> <np num>    # e.g. create np 9 1",
        "create dn                     # e.g. create dn",
        "add disk <disk num>           # e.g. add disk 4",
        "set loglevel <level>          # e.g. set loglevel 5",
        "[show|diag] mem",
        "[quit|help]"      
        "[show|diag] mem",
        "<quit|help>"
    };
    int usage_size = sizeof(usage)/sizeof(usage[0]);
    UINT32 crfs_md_id;

    init();

    c_history_init(cmd_his_tbl, cmd_his_max, &cmd_his_size);

    crfs_root_dir = NULL_PTR;
    crfs_md_id = ERR_MODULE_ID;
    sys_log(LOGCONSOLE, "[DEBUG] argc = %d\n", argc);
  
    for(idx = 1;idx < argc; idx ++)
    {
        char *seg[8];
        uint16_t seg_num;

        BSET(cmd_line,'\0',cmd_line_len);

        snprintf(cmd_line, cmd_line_len - 1, "%s", argv[idx]);
      
        sys_log(LOGCONSOLE, "cmd: %s\n", cmd_line);

        if(0 == strlen(cmd_line))
        {
            continue;
        }

        c_history_push(cmd_his_tbl, cmd_his_max, &cmd_his_size, c_str_dup(cmd_line));

        seg_num = c_str_split(cmd_line, " \t\n\r", seg, sizeof(seg)/sizeof(seg[0]));

        if(1 == seg_num && EC_TRUE == __crfs_test_check_str_in(seg[0], "print:p"))
        {
            __crfs_test_no_md_continue(crfs_md_id);
            crfs_print_module_status(crfs_md_id, LOGCONSOLE);
            continue;
        }

        if(2 == seg_num && EC_TRUE == __crfs_test_check_str_in(seg[0], "print:p")
                        && EC_TRUE == __crfs_test_check_str_in(seg[1], "np"))
        {
            __crfs_test_no_md_continue(crfs_md_id);
            crfs_show_npp(crfs_md_id, LOGCONSOLE);
            continue;
        }  

        if(2 == seg_num && EC_TRUE == __crfs_test_check_str_in(seg[0], "print:p")
                        && EC_TRUE == __crfs_test_check_str_in(seg[1], "dn"))
        {
            __crfs_test_no_md_continue(crfs_md_id);
            crfs_show_dn(crfs_md_id, LOGCONSOLE);
            continue;
        }   

        if(4 == seg_num && EC_TRUE == __crfs_test_check_str_in(seg[0], "create:cr:c")
                        && EC_TRUE == __crfs_test_check_str_in(seg[1], "np"))
        {          
            UINT32  crfsnp_model;
            UINT32  crfsnp_max_num;
            CSTRING *crfsnp_root_dir;

            __crfs_test_no_md_continue(crfs_md_id);

            crfsnp_model             = c_str_to_word(seg[2]);
            crfsnp_max_num           = c_str_to_word(seg[3]);

            crfsnp_root_dir = cstring_make("%s/rfs%02ld", (char *)cstring_get_str(crfs_root_dir), crfs_md_id);
            ASSERT(NULL_PTR != crfsnp_root_dir);
          
            if(EC_FALSE == crfs_create_npp(crfs_md_id, crfsnp_model, crfsnp_max_num, 1/*hash algo*/, crfsnp_root_dir))
            {
                sys_log(LOGCONSOLE, "error:create crfs npp failed\n");
            }
            else
            {
                sys_log(LOGCONSOLE, "[DEBUG] create crfs npp done\n");
            }
            cstring_free(crfsnp_root_dir);
            continue;
        }

        if(2 == seg_num && EC_TRUE == __crfs_test_check_str_in(seg[0], "create:cr:c")
                        && EC_TRUE == __crfs_test_check_str_in(seg[1], "dn"))
        {
            CSTRING *crfsdn_root_dir;

            __crfs_test_no_md_continue(crfs_md_id);

            crfsdn_root_dir = cstring_make("%s/rfs%02ld", (char *)cstring_get_str(crfs_root_dir), crfs_md_id);
            ASSERT(NULL_PTR != crfsdn_root_dir);

            if(EC_FALSE == crfs_create_dn(crfs_md_id, crfsdn_root_dir))
            {
                sys_log(LOGCONSOLE, "error:create crfs dn failed\n");
            }
            else
            {
                sys_log(LOGCONSOLE, "[DEBUG] create crfs dn done\n");
            }
            cstring_free(crfsdn_root_dir);
            continue;
        }      

        if(3 == seg_num && EC_TRUE == __crfs_test_check_str_in(seg[0], "add:a")
                        && EC_TRUE == __crfs_test_check_str_in(seg[1], "disk:dsk:d"))
        {          
            UINT32 disk_no;

            __crfs_test_no_md_continue(crfs_md_id);

            disk_no = c_str_to_word(seg[2]);

            if(EC_FALSE == crfs_add_disk(crfs_md_id, disk_no))
            {
                sys_log(LOGCONSOLE, "error:add disk %ld failed\n", disk_no);
            }
            else
            {
                sys_log(LOGCONSOLE, "[DEBUG] add disk %ld done\n", disk_no);
            }

            continue;
        }          

        if(3 == seg_num && EC_TRUE == __crfs_test_check_str_in(seg[0], "open:o")
                        && EC_TRUE == __crfs_test_check_str_in(seg[1], "rfs"))
        {
            if(ERR_MODULE_ID != crfs_md_id)
            {
                sys_log(LOGCONSOLE, "error: crfs md %u was open, pls close it at first\n", crfs_md_id);
                continue;
            }

            ASSERT(NULL_PTR == crfs_root_dir);

            crfs_root_dir = cstring_new((UINT8 *)seg[2], 0);
          
            crfs_md_id = crfs_start(crfs_root_dir);
            if(ERR_MODULE_ID == crfs_md_id)
            {
                sys_log(LOGCONSOLE, "error:open crfs failed\n");
            }
            else
            {
                sys_log(LOGCONSOLE, "[DEBUG] open crfs done\n");
            }
            continue;
        }

        if(2 == seg_num && EC_TRUE == __crfs_test_check_str_in(seg[0], "close:c")
                        && EC_TRUE == __crfs_test_check_str_in(seg[1], "rfs"))
        { 
            __crfs_test_no_md_continue(crfs_md_id);
          
            crfs_end(crfs_md_id);
            crfs_md_id = ERR_MODULE_ID;

            cstring_free(crfs_root_dir);
            crfs_root_dir = NULL_PTR;
            continue;
        } 

        if(3 == seg_num
        && EC_TRUE == __crfs_test_check_str_in(seg[0], "set:s")
        && EC_TRUE == __crfs_test_check_str_in(seg[1], "loglevel:log:l"))
        {
            uint32_t level;
            level = c_str_to_word(seg[2]);      
            set_log_level(level);
            continue;
        }     

        if(2 == seg_num
        && EC_TRUE == __crfs_test_check_str_in(seg[0], "print:p")
        && EC_TRUE == __crfs_test_check_str_in(seg[1], "loglevel:log:l"))
        {
            uint32_t level;
            level = c_str_to_word(seg[2]);      
            print_log_level();
            continue;
        }       

        if(1 == seg_num && EC_TRUE == __crfs_test_check_str_in(seg[0], "help:h"))
        {
            c_usage_print(LOGCONSOLE, usage, usage_size);
            continue;
        }  
        if(2 == seg_num && EC_TRUE == __crfs_test_check_str_in(seg[0], "show") && EC_TRUE == __crfs_test_check_str_in(seg[1], "mem"))
        {
            print_static_mem_status(LOGCONSOLE);
            continue;
        }  
        if(2 == seg_num && EC_TRUE == __crfs_test_check_str_in(seg[0], "diag") && EC_TRUE == __crfs_test_check_str_in(seg[1], "mem"))
        {
            print_static_mem_diag_info(LOGCONSOLE);
            continue;
        }      
        if(1 == seg_num && EC_TRUE == __crfs_test_check_str_in(seg[0], "history:his"))
        {
            c_history_print(LOGCONSOLE, cmd_his_tbl, cmd_his_max, cmd_his_size);
            continue;
        }       
        if(1 == seg_num && EC_TRUE == __crfs_test_check_str_in(seg[0], "quit:q:exit:e"))
        {
            break;
        }      
    }  

    c_history_clean(cmd_his_tbl, cmd_his_max, cmd_his_size);

    if(ERR_MODULE_ID != crfs_md_id)
    {
        crfs_end(crfs_md_id);
        crfs_md_id = ERR_MODULE_ID;
    }

    if(NULL_PTR != crfs_root_dir)
    {
        cstring_free(crfs_root_dir);
        crfs_root_dir = NULL_PTR;
    }

    deinit();

    print_static_mem_status(LOGCONSOLE);
    print_static_mem_diag_info(LOGCONSOLE);
  
    return (0);
}

int main(int argc, char **argv)
{
    if(2 == argc)
    {
        char *cmd[32];
        uint16_t cmd_num;
  
        cmd_num = c_str_split(argv[1], ";", cmd, sizeof(cmd)/sizeof(cmd[0]));
        return __crfs_test_suite_0(cmd_num, cmd);
    }
  
    return __crfs_test_suite_0(argc, argv);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

