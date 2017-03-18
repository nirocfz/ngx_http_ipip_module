#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define B2IL(b) (((b)[0] & 0xFF) | (((b)[1] << 8) & 0xFF00) | (((b)[2] << 16) & 0xFF0000) | (((b)[3] << 24) & 0xFF000000))
#define B2IU(b) (((b)[3] & 0xFF) | (((b)[2] << 8) & 0xFF00) | (((b)[1] << 16) & 0xFF0000) | (((b)[0] << 24) & 0xFF000000))

typedef struct {
    u_char         *data;
    u_char         *index;
    uint32_t       *flag;
    uint32_t        offset;
} ngx_http_ipip_value_t;

typedef struct {
    ngx_str_t                 file;
    ngx_http_ipip_value_t    *ipip;
} ngx_http_ipip_loc_conf_t;

static void * ngx_http_ipip_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_ipip_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_buf_t * ngx_http_ipip_find(ngx_http_ipip_value_t *ipip, ngx_http_request_t *r);

static ngx_command_t ngx_http_ipip_commands[] = {

    { ngx_string("ipip_file"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_ipip_file,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
      ngx_null_command
};

static ngx_http_module_t ngx_http_ipip_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_ipip_create_loc_conf,         /* create location configuration */
    NULL                                   /* merge location configuration */

};

ngx_module_t  ngx_http_ipip_module = {
    NGX_MODULE_V1,
    &ngx_http_ipip_module_ctx,             /* module context */
    ngx_http_ipip_commands,                /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_ipip_handler(ngx_http_request_t *r)
{
    ngx_connection_t          *c;
    ngx_buf_t                 *b;
    ngx_chain_t                out;
    ngx_int_t                  rc;
    ngx_http_ipip_loc_conf_t  *ilcf;
    ngx_http_ipip_value_t     *ipip;

    c = r->connection;
    ilcf = ngx_http_get_module_loc_conf(r, ngx_http_ipip_module);
    ipip = ilcf->ipip;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
            "http request from \"%V\", args: %V, uri: %V", &c->addr_text, &r->args, &r->uri);

    b = ngx_http_ipip_find(ipip, r);
    if (b == NULL) {
        return NGX_HTTP_NO_CONTENT;;
    }

    r->headers_out.status = NGX_HTTP_OK;
    ngx_str_set(&r->headers_out.content_type, "text/plain");
    r->headers_out.content_type_len = r->headers_out.content_type.len;
    r->headers_out.content_type_lowcase = NULL;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b->last_buf = 1;
    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}

static void *
ngx_http_ipip_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_ipip_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ipip_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}

static char *
ngx_http_ipip_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                     *rv;
    ngx_http_core_loc_conf_t *clcf;
    ngx_file_t                file;
    ngx_file_info_t           fi;
    ngx_http_ipip_value_t    *ipip;
    size_t                    size;
    ssize_t                   n;
    uint32_t                  length;
    ngx_http_ipip_loc_conf_t *ilcf = conf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_ipip_handler;
    ngx_conf_set_str_slot(cf, cmd, conf);

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.name = ilcf->file;
    file.log = cf->log;
    file.fd = ngx_open_file(ilcf->file.data, NGX_FILE_RDONLY, 0, 0);
    if (file.fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, 0, ngx_open_file_n " \"%V\" failed", &ilcf->file);
        return NGX_CONF_ERROR;
    }
    if (ngx_fd_info(file.fd, &fi) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, 0, ngx_file_info_n " \"%V\" failed", &ilcf->file);
        goto failed;
    }

    size = (size_t) ngx_file_size(&fi);

    ilcf->ipip = ngx_pcalloc(cf->pool, sizeof(ngx_http_ipip_value_t));
    if (ilcf->ipip == NULL) {
        goto failed;
    }
    ipip = ilcf->ipip;

    ipip->data = ngx_palloc(cf->pool, size);
    if (ipip->data == NULL) {
        goto failed;
    }

    n = ngx_read_file(&file, ipip->data, size, 0);
    if (n == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                           ngx_read_file_n " \"%V\" failed", &ilcf->file);
        goto failed;
    }

    length = B2IU(ipip->data);
    if (length == 0) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, 0, "invalid ipip data file \"%V\"", &ilcf->file);
        goto failed;
    }
    ipip->index = ngx_palloc(cf->pool, length);
    if (ipip->index == NULL) {
        goto failed;
    }
    ngx_memcpy(ipip->index, ipip->data + 4, length);
    ipip->offset = length;
    ipip->flag = ngx_palloc(cf->pool, 256 * sizeof(uint32_t));
    ngx_memcpy(ipip->flag, ipip->index, 256 * sizeof(uint32_t));
    rv = NGX_CONF_OK;
    goto done;

failed:
    rv = NGX_CONF_ERROR;
done:
    if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
                      ngx_close_file_n " \"%V\" failed", &ilcf->file);
    }
    return rv;
}

static ngx_buf_t *
ngx_http_ipip_find(ngx_http_ipip_value_t *ipip, ngx_http_request_t *r)
{
    ngx_buf_t     *b;
    u_char       *text;
    uint32_t       ips[4];

    if (ipip == NULL) {
        return NULL;
    }
    if (r->uri.len > 1)  {
        text = r->uri.data + 1;
    } else {
        text = r->connection->addr_text.data;
    }
    int num = sscanf((const char *)text, "%d.%d.%d.%d", &ips[0], &ips[1], &ips[2], &ips[3]);
    if (num == 4) {
        uint32_t ip_prefix_value = ips[0];
        uint32_t ip2long_value = B2IU(ips);
        uint32_t start = ipip->flag[ip_prefix_value];
        uint32_t max_comp_len = ipip->offset - 1028;
        uint32_t index_offset = 0;
        uint32_t index_length = 0;
        for (start = start * 8 + 1024; start < max_comp_len; start += 8) {
            if (B2IU(ipip->index + start) >= ip2long_value) {
                index_offset = B2IL(ipip->index + start + 4) & 0x00FFFFFF;
                index_length = ipip->index[start + 7];
                break;
            }
        }
        if (index_length == 0) {
            return NULL;
        }
        b = ngx_create_temp_buf(r->pool, index_length);
        if (b == NULL) {
            return NULL;
        }

        b->last = ngx_cpymem(b->last, ipip->data + ipip->offset + index_offset - 1024, index_length);
        return b;
    } else {
        return NULL;
    }
}
