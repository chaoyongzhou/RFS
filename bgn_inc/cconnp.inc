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

#ifndef _CCONNP_INC
#define _CCONNP_INC

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "type.h"
#include "cstring.h"
#include "clist.h"
#include "crb.h"
#include "csocket.inc"

typedef void  *  (* CCONNP_DATA_NEW)();
typedef EC_BOOL  (* CCONNP_DATA_FREE)(void *);
typedef EC_BOOL  (* CCONNP_CONNECT)(const UINT32, const UINT32, int *);
typedef EC_BOOL  (* CCONNP_SEND)(CSOCKET_CNODE *, const UINT8 *, const UINT32, UINT32 *);
typedef EC_BOOL  (* CCONNP_RECV)(CSOCKET_CNODE *, const UINT8 *, const UINT32, UINT32 *);
typedef EC_BOOL  (* CCONNP_CLOSE)(CSOCKET_CNODE *);
typedef EC_BOOL  (* CCONNP_TIMEOUT)(CSOCKET_CNODE *);
typedef EC_BOOL  (* CCONNP_SHAKEHAND_SEND)(CSOCKET_CNODE *);
typedef EC_BOOL  (* CCONNP_SHAKEHAND_RECV)(CSOCKET_CNODE *);
typedef EC_BOOL  (* CCONNP_BEFORE_SEND)(CSOCKET_CNODE *);
typedef EC_BOOL  (* CCONNP_AFTER_SEND)(CSOCKET_CNODE *);
typedef EC_BOOL  (* CCONNP_HEALTH_CHECKER)(CSOCKET_CNODE *);

/*connection pool*/
typedef struct
{
    UINT32                         srv_ipaddr;
    UINT32                         srv_port;
    
    UINT32                         srv_tcid;
    UINT32                         srv_comm;
    UINT32                         srv_size;

    UINT32                         timeout_msec;
    UINT32                         expired_msec;

    CCONNP_DATA_NEW                data_new;
    CCONNP_DATA_FREE               data_free;
    CCONNP_CONNECT                 connect;
    CCONNP_SEND                    send;
    CCONNP_RECV                    recv;
    CCONNP_CLOSE                   close;
    CCONNP_TIMEOUT                 timeout;
    CCONNP_SHAKEHAND_SEND          shakehand_send;
    CCONNP_SHAKEHAND_RECV          shakehand_recv;
    CCONNP_BEFORE_SEND             before_send;    /*before sending any data*/
    CCONNP_AFTER_SEND              after_send;     /*after sent out all data*/
    CCONNP_HEALTH_CHECKER          health_checker;

    CLIST                          send_data_list;/*item is protocol data*/
    
    CQUEUE                         idle_conn_queue; /*FIFO*/
}CCONNP;

#define CCONNP_SRV_IPADDR(cconnp)                    ((cconnp)->srv_ipaddr)
#define CCONNP_SRV_PORT(cconnp)                      ((cconnp)->srv_port)

#define CCONNP_SRV_IPADDR_STR(cconnp)                c_word_to_ipv4(CCONNP_SRV_IPADDR(cconnp))

#define CCONNP_SRV_TCID(cconnp)                      ((cconnp)->srv_tcid)
#define CCONNP_SRV_COMM(cconnp)                      ((cconnp)->srv_comm)
#define CCONNP_SRV_SIZE(cconnp)                      ((cconnp)->srv_size)

#define CCONNP_SRV_TCID_STR(cconnp)                  c_word_to_ipv4(CCONNP_SRV_TCID(cconnp))

#define CCONNP_TIMEOUT_MSEC(cconnp)                  ((cconnp)->timeout_msec)
#define CCONNP_EXPIRED_MSEC(cconnp)                  ((cconnp)->expired_msec)

#define CCONNP_DATA_NEW_HANDLER(cconnp)              ((cconnp)->data_new)
#define CCONNP_DATA_FREE_HANDLER(cconnp)             ((cconnp)->data_free)

#define CCONNP_CONNECT_HANDLER(cconnp)               ((cconnp)->connect)
#define CCONNP_SEND_HANDLER(cconnp)                  ((cconnp)->send)
#define CCONNP_RECV_HANDLER(cconnp)                  ((cconnp)->recv)
#define CCONNP_CLOSE_HANDLER(cconnp)                 ((cconnp)->close)
#define CCONNP_TIMEOUT_HANDLER(cconnp)               ((cconnp)->timeout)

#define CCONNP_SHAKEHAND_SEND_HANDLER(cconnp)        ((cconnp)->shakehand_send)
#define CCONNP_SHAKEHAND_RECV_HANDLER(cconnp)        ((cconnp)->shakehand_recv)

#define CCONNP_BEFORE_SEND_HANDLER(cconnp)           ((cconnp)->before_send)
#define CCONNP_AFTER_SEND_HANDLER(cconnp)            ((cconnp)->after_send)

#define CCONNP_HEALTH_CHECKER_HANDLER(cconnp)        ((cconnp)->health_checker)

#define CCONNP_SEND_DATA_LIST(cconnp)                (&((cconnp)->send_data_list))
#define CCONNP_IDLE_CONN_QUEUE(cconnp)               (&((cconnp)->idle_conn_queue))

/*manager of several connection pool*/
typedef struct
{
    CRB_TREE             cconnp_tree; /*item is CCONNP*/
}CCONNP_MGR;

#define CCONNP_MGR_TREE(cconnp_mgr)                  (&((cconnp_mgr)->cconnp_tree))

#endif/*_CCONNP_INC*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

