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

#ifndef _CHTTPS_H
#define _CHTTPS_H

#include <arpa/inet.h>    
#include <openssl/ssl.h>    
#include <openssl/err.h> 

#include "type.h"
#include "debug.h"

#include "http_parser.h"
#include "cbuffer.h"
#include "chunk.h"

#include "chttps.inc"
#include "csrv.h"

/*---------------------------------------- INTERFACE WITH HTTP NODE  ----------------------------------------*/
CHTTPS_NODE *chttps_node_new(const UINT32 type);

EC_BOOL chttps_node_init(CHTTPS_NODE *chttps_node, const UINT32 type);

EC_BOOL chttps_node_clean(CHTTPS_NODE *chttps_node);

EC_BOOL chttps_node_free(CHTTPS_NODE *chttps_node);

EC_BOOL chttps_node_clear(CHTTPS_NODE *chttps_node);/*note: chttps_node_clear is ONLY for memory recycle asap before it comes to life-cycle end*/

EC_BOOL chttps_node_wait_resume(CHTTPS_NODE *chttps_node);

void    chttps_node_print(LOG *log, const CHTTPS_NODE *chttps_node);

EC_BOOL chttps_node_is_chunked(const CHTTPS_NODE *chttps_node);

EC_BOOL chttps_node_is_norange(const CHTTPS_NODE *chttps_node);

EC_BOOL chttps_node_recv(CHTTPS_NODE *chttps_node, CSOCKET_CNODE *csocket_cnode);

EC_BOOL chttps_node_send(CHTTPS_NODE *chttps_node, CSOCKET_CNODE *csocket_cnode);

EC_BOOL chttps_node_need_send(CHTTPS_NODE *chttps_node);

EC_BOOL chttps_node_need_parse(CHTTPS_NODE *chttps_node);

EC_BOOL chttps_node_has_data_in(CHTTPS_NODE *chttps_node);

/*---- TODO BEG : replace these interfaces by macros*/
EC_BOOL chttps_node_recv_export_to_cbytes(CHTTPS_NODE *chttps_node, CBYTES *cbytes, const UINT32 body_len);

EC_BOOL chttps_node_recv_clean(CHTTPS_NODE *chttps_node);

/*for debug only*/
CHUNK_MGR *chttps_node_recv_chunks(const CHTTPS_NODE *chttps_node);

/*for debug only*/
UINT32  chttps_node_recv_chunks_num(const CHTTPS_NODE *chttps_node);


/*for debug only*/
UINT32  chttps_node_recv_len(const CHTTPS_NODE *chttps_node);

/*for debug only*/
UINT32 chttps_node_send_len(const CHTTPS_NODE *chttps_node);

EC_BOOL chttps_node_add_header(CHTTPS_NODE *chttps_node, const char *k, const char *v);

char   *chttps_node_get_header(CHTTPS_NODE *chttps_node, const char *k);

EC_BOOL chttps_node_del_header(CHTTPS_NODE *chttps_node, const char *k);

EC_BOOL chttps_node_renew_header(CHTTPS_NODE *chttps_node, const char *k, const char *v);

EC_BOOL chttps_node_fetch_header(CHTTPS_NODE *chttps_node, const char *k, CSTRKV_MGR *cstrkv_mgr);

EC_BOOL chttps_node_fetch_headers(CHTTPS_NODE *chttps_node, const char *keys, CSTRKV_MGR *cstrkv_mgr);

EC_BOOL chttps_node_has_header_key(CHTTPS_NODE *chttps_node, const char *k);

EC_BOOL chttps_node_has_header(CHTTPS_NODE *chttps_node, const char *k, const char *v);

uint64_t chttps_node_fetch_file_size(CHTTPS_NODE *chttps_node);
  
/*---- TODO END : replace these interfaces by macros*/

/*---------------------------------------- HTTP HEADER PASER  ----------------------------------------*/

EC_BOOL chttps_parse_host(CHTTPS_NODE *chttps_node);

EC_BOOL chttps_parse_content_length(CHTTPS_NODE *chttps_node);

EC_BOOL chttps_parse_connection_keepalive(CHTTPS_NODE *chttps_node);

EC_BOOL chttps_parse_uri(CHTTPS_NODE *chttps_node);

EC_BOOL chttps_parse(CHTTPS_NODE *chttps_node);

EC_BOOL chttps_pause_parser(http_parser_t* http_parser);

EC_BOOL chttps_resume_parser(http_parser_t* http_parser);

/*---------------------------------------- MAKE RESPONSE ----------------------------------------*/
EC_BOOL chttps_make_response_header_protocol(CHTTPS_NODE *chttps_node, const uint16_t major, const uint16_t minor, const uint32_t status);

EC_BOOL chttps_make_response_header_keepalive(CHTTPS_NODE *chttps_node);

EC_BOOL chttps_make_response_header_date(CHTTPS_NODE *chttps_node);

EC_BOOL chttps_make_response_header_expires(CHTTPS_NODE *chttps_node);

EC_BOOL chttps_make_response_header_token(CHTTPS_NODE *chttps_node, const uint8_t *token, const uint32_t len);

/*general interface: append data to header buffer*/
EC_BOOL chttps_make_response_header_data(CHTTPS_NODE *chttps_node, const uint8_t *data, const uint32_t len);

EC_BOOL chttps_make_response_header_retire(CHTTPS_NODE *chttps_node, const uint8_t *retire_result, const uint32_t len);

EC_BOOL chttps_make_response_header_recycle(CHTTPS_NODE *chttps_node, const uint8_t *recycle_result, const uint32_t len);

EC_BOOL chttps_make_response_header_elapsed(CHTTPS_NODE *chttps_node);

EC_BOOL chttps_make_response_header_content_type(CHTTPS_NODE *chttps_node, const uint8_t *data, const uint32_t size);

EC_BOOL chttps_make_response_header_content_length(CHTTPS_NODE *chttps_node, const uint64_t size);

EC_BOOL chttps_make_response_header_kv(CHTTPS_NODE *chttps_node, const CSTRKV *cstrkv);

EC_BOOL chttps_make_response_header_kvs(CHTTPS_NODE *chttps_node);

EC_BOOL chttps_make_response_header_end(CHTTPS_NODE *chttps_node);

EC_BOOL chttps_make_response_body(CHTTPS_NODE *chttps_node, const uint8_t *data, const uint32_t size);

/*make response body without data copying but data transfering*/
EC_BOOL chttps_make_response_body_ext(CHTTPS_NODE *chttps_node, const uint8_t *data, const uint32_t size);

EC_BOOL chttps_make_response_header_common(CHTTPS_NODE *chttps_node, const uint64_t body_len);

EC_BOOL chttps_make_error_response(CHTTPS_NODE *chttps_node);

/*---------------------------------------- HTTP SERVER ----------------------------------------*/
CSRV * chttps_srv_start(const UINT32 srv_ipaddr, const UINT32 srv_port, const UINT32 md_id, 
                     const uint32_t timeout_nsec,
                     CSRV_INIT_CSOCKET_CNODE       init_csocket_cnode,
                     CSRV_ADD_CSOCKET_CNODE        add_csocket_cnode, 
                     CSRV_DEL_CSOCKET_CNODE        del_csocket_cnode,
                     CSRV_RD_HANDLER_FUNC          rd_handler,
                     CSRV_WR_HANDLER_FUNC          wr_handler,
                     CSRV_TIMEOUT_HANDLER_FUNC     timeout_handler,
                     CSRV_COMPLETE_HANDLER_FUNC    complete_handler,
                     CSRV_CLOSE_HANDLER_FUNC       close_handler
                     );

EC_BOOL chttps_srv_end(CSRV *csrv);

EC_BOOL chttps_srv_bind_modi(CSRV *csrv, const UINT32 modi);

EC_BOOL chttps_srv_accept_once(CSRV *csrv, EC_BOOL *continue_flag);

EC_BOOL chttps_srv_accept(CSRV *csrv);

/*---------------------------------------- COMMIT RESPONSE FOR EMITTING  ----------------------------------------*/
EC_BOOL chttps_commit_error_response(CHTTPS_NODE *chttps_node);

EC_BOOL chttps_commit_error_request(CHTTPS_NODE *chttps_node);

/*---------------------------------------- SEND AND RECV MANAGEMENT  ----------------------------------------*/
EC_BOOL chttps_csocket_cnode_init(const UINT32 UNUSED(md_id), CSOCKET_CNODE *csocket_cnode);

EC_BOOL chttps_csocket_cnode_close(CSOCKET_CNODE *csocket_cnode);
EC_BOOL chttps_csocket_cnode_force_close(CSOCKET_CNODE *csocket_cnode);

EC_BOOL chttps_csocket_cnode_recv_req(CSOCKET_CNODE *csocket_cnode);

EC_BOOL chttps_csocket_cnode_send_rsp(CSOCKET_CNODE *csocket_cnode);

/*---------------------------------------- REQUEST REST LIST MANAGEMENT ----------------------------------------*/
CHTTPS_REST *chttps_rest_new();

EC_BOOL chttps_rest_init(CHTTPS_REST *chttps_rest);

EC_BOOL chttps_rest_clean(CHTTPS_REST *chttps_rest);

EC_BOOL chttps_rest_free(CHTTPS_REST *chttps_rest);

void    chttps_rest_print(LOG *log, const CHTTPS_REST *chttps_rest);

EC_BOOL chttps_rest_cmp(const CHTTPS_REST *chttps_rest_1st, const CHTTPS_REST *chttps_rest_2nd);

EC_BOOL chttps_rest_list_push(const char *name, EC_BOOL (*commit)(CHTTPS_NODE *));

CHTTPS_REST *chttps_rest_list_pop(const char *name, const uint32_t len);

CHTTPS_REST *chttps_rest_list_find(const char *name, const uint32_t len);

/*---------------------------------------- REQUEST DEFER QUEUE MANAGEMENT ----------------------------------------*/

EC_BOOL chttps_defer_request_queue_init();

EC_BOOL chttps_defer_request_queue_clean();

EC_BOOL chttps_defer_request_queue_is_empty();

EC_BOOL chttps_defer_request_queue_push(CHTTPS_NODE *chttps_node);

EC_BOOL chttps_defer_request_queue_erase(CHTTPS_NODE *chttps_node);

CHTTPS_NODE *chttps_defer_request_queue_pop();

CHTTPS_NODE *chttps_defer_request_queue_peek();

EC_BOOL chttps_defer_request_commit(CHTTPS_NODE *chttps_node);

EC_BOOL chttps_defer_request_queue_launch(CHTTPS_NODE_COMMIT_REQUEST chttps_node_commit_request);


/*-------------------------------------------------------------------------------------------------------------------------------------------\
 *
 * Send Http Request and Handle Http Response
 *
\*-------------------------------------------------------------------------------------------------------------------------------------------*/

EC_BOOL chttps_node_encode_req_const_str(CHTTPS_NODE *chttps_node, const uint8_t *str, const UINT32 len);

EC_BOOL chttps_node_encode_req_protocol(CHTTPS_NODE *chttps_node, const uint16_t version_major, const uint16_t version_minor);

EC_BOOL chttps_node_encode_req_method(CHTTPS_NODE *chttps_node, const CSTRING *method);

EC_BOOL chttps_node_encode_req_header_kv(CHTTPS_NODE *chttps_node, const CSTRKV *kv);

EC_BOOL chttps_node_encode_req_param_kv(CHTTPS_NODE *chttps_node, const CSTRKV *kv);

EC_BOOL chttps_node_encode_req_param(CHTTPS_NODE *chttps_node, const CSTRKV_MGR *param);

EC_BOOL chttps_node_encode_req_uri(CHTTPS_NODE *chttps_node , const CSTRING *uri, const CSTRKV_MGR *param);

EC_BOOL chttps_node_encode_req_header_end(CHTTPS_NODE *chttps_node);

EC_BOOL chttps_node_encode_req_header(CHTTPS_NODE *chttps_node, const CSTRING *method, const CSTRING *uri, const CSTRKV_MGR *param, const CSTRKV_MGR *header);

EC_BOOL chttps_node_encode_req_header_line(CHTTPS_NODE *chttps_node, const CSTRING *method, const CSTRING *uri, const CSTRKV_MGR *param, 
                                            const uint16_t version_major, const uint16_t version_minor);
EC_BOOL chttps_node_encode_req_body(CHTTPS_NODE *chttps_node, const CBYTES *req_body);

EC_BOOL chttps_node_encode_rsp_const_str(CHTTPS_NODE *chttps_node, const uint8_t *str, const UINT32 len, CBYTES *cbytes);

EC_BOOL chttps_node_encode_rsp_protocol(CHTTPS_NODE *chttps_node, const uint16_t version_major, const uint16_t version_minor, CBYTES *cbytes);

EC_BOOL chttps_node_encode_rsp_method(CHTTPS_NODE *chttps_node, const CSTRING *method, CBYTES *cbytes);

EC_BOOL chttps_node_encode_rsp_status(CHTTPS_NODE *chttps_node, const uint32_t status_code, CBYTES *cbytes);

EC_BOOL chttps_node_encode_rsp_header_kv(CHTTPS_NODE *chttps_node, const CSTRKV *kv, CBYTES *cbytes);

EC_BOOL chttps_node_encode_rsp_param_kv(CHTTPS_NODE *chttps_node, const CSTRKV *kv, CBYTES *cbytes);

EC_BOOL chttps_node_encode_rsp_param(CHTTPS_NODE *chttps_node, const CSTRKV_MGR *param, CBYTES *cbytes);

EC_BOOL chttps_node_encode_rsp_uri(CHTTPS_NODE *chttps_node , const CSTRING *uri, const CSTRKV_MGR *param, CBYTES *cbytes);

EC_BOOL chttps_node_encode_rsp_header_line(CHTTPS_NODE *chttps_node, const CSTRING *method, const CSTRING *uri, const CSTRKV_MGR *param, 
                                            const uint16_t version_major, const uint16_t version_minor, CBYTES *cbytes);

EC_BOOL chttps_node_encode_rsp_header_end(CHTTPS_NODE *chttps_node, CBYTES *cbytes);

EC_BOOL chttps_node_encode_rsp_header(CHTTPS_NODE *chttps_node, const UINT32 status_code, const CSTRKV_MGR *header, CBYTES *cbytes);

EC_BOOL chttps_node_encode_rsp_body(CHTTPS_NODE *chttps_node, CBYTES *cbytes);

EC_BOOL chttps_node_encode_rsp(CHTTPS_NODE *chttps_node, CBYTES *cbytes);

EC_BOOL chttps_node_connect(CHTTPS_NODE *chttps_node, const UINT32 ipaddr, const UINT32 port);

EC_BOOL chttps_csocket_cnode_handshake_on_client(CSOCKET_CNODE *csocket_cnode);

EC_BOOL chttps_csocket_cnode_handshake_on_server(CSOCKET_CNODE *csocket_cnode);
  
EC_BOOL chttps_csocket_cnode_send_req(CSOCKET_CNODE *csocket_cnode);

EC_BOOL chttps_csocket_cnode_recv_rsp(CSOCKET_CNODE *csocket_cnode);

/*-------------------------------------------------------------------------------------------------------------------------------------------\
 *
 * Basic Http Flow
 *
\*-------------------------------------------------------------------------------------------------------------------------------------------*/

EC_BOOL chttps_request_basic(const CHTTP_REQ *chttp_req, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat);

/*-------------------------------------------------------------------------------------------------------------------------------------------\
 *
 * Try to connect remote http server to check connectivity (HEALTH CHECKER)
 *
\*-------------------------------------------------------------------------------------------------------------------------------------------*/

EC_BOOL chttps_csocket_cnode_check(CSOCKET_CNODE *csocket_cnode);

EC_BOOL chttps_node_check(CHTTPS_NODE *chttps_node, const UINT32 ipaddr, const UINT32 port);

EC_BOOL chttps_check(const CHTTP_REQ *chttp_req, CHTTP_STAT *chttp_stat);

/*-------------------------------------------------------------------------------------------------------------------------------------------\
 *
 * General Http Request Entry
 *
\*-------------------------------------------------------------------------------------------------------------------------------------------*/

EC_BOOL chttps_request(const CHTTP_REQ *chttp_req, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat);


/*----------------------------------------  CHTTPS SEND & RECV  ----------------------------------------*/

EC_BOOL chttps_ssl_send(CHTTPS_NODE *chttps_node, const UINT32 once_max_size, const UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *pos);
EC_BOOL chttps_ssl_recv(CHTTPS_NODE *chttps_node, const UINT32 once_max_size, UINT8 *in_buff, const UINT32 in_buff_expect_len, UINT32 *pos);
EC_BOOL chttps_send(CHTTPS_NODE *chttps_node, CSOCKET_CNODE *csocket_cnode, const UINT8 * out_buff, const UINT32 out_buff_max_len, UINT32 * pos);
EC_BOOL chttps_recv(CHTTPS_NODE *chttps_node, CSOCKET_CNODE *csocket_cnode, UINT8 *in_buff, const UINT32 in_buff_expect_len, UINT32 *pos);

#endif /*_CHTTPS_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

