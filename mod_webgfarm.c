/*
 * Copyright (C) 2014 Fuyumasa Takatsu
 *
 * Licensed under the Apache License, Version 2.0 (the &quot;License&quot;);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an &quot;AS IS&quot; BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ap_config.h"
#include "apr.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_network_io.h"
#include "apr_want.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_request.h"
#include "http_protocol.h"
#include "util_script.h"

#include <gfarm/gfarm.h>
#include <stdlib.h>

#ifndef WEBGFARM_BUFFER_SIZE
#define WEBGFARM_BUFFER_SIZE 4096
#endif

#ifndef WEBGFFARM_MAX_POST_SIZE
#define WEBGFFARM_MAX_POST_SIZE 134217728 //128MiB
#endif

#ifndef WEBGFARM_TABLE_SIZE
#define WEBGFARM_TABLE_SIZE 4096
#endif

module AP_MODULE_DECLARE_DATA webgfarm_module;

typedef struct {
    int enabled;
    int read_redirect;
    int write_redirect;
    const char *localhost;
    int localhostlen;
    const char *basepath;
    int basepathlen;
    int ssl;
    apr_table_t *hosts;
} webgfarm_config;

static void *webgfarm_create_server_config(apr_pool_t *p, server_rec *s) {
    webgfarm_config *wconfig = apr_pcalloc(p, sizeof (webgfarm_config));
    wconfig->enabled = 0;
    wconfig->read_redirect = 0;
    wconfig->write_redirect = 0;
    wconfig->hosts = apr_table_make(p, WEBGFARM_TABLE_SIZE);
    wconfig->localhost = NULL;
    wconfig->localhostlen = 0;
    wconfig->basepath = NULL;
    wconfig->basepathlen = 0;
    wconfig->ssl = 0;
    return wconfig;
}

int isdir(char *filepath) {
    return filepath[strlen(filepath) - 1] == '/';
}

char* parse_form_from_POST(request_rec *r, int *in_size_) {
    char *buf;
    int in_size;
    apr_status_t rv;
    apr_bucket_brigade *bbin;
    apr_size_t bbin_size;
    const char *clen = apr_table_get(r->headers_in, "Content-Length");
    if (clen != NULL) {
        in_size = strtol(clen, NULL, 0);
        if (in_size >= WEBGFFARM_MAX_POST_SIZE) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Content-Length too big. Content-Length: %d bytes; limit: %d", in_size, WEBGFFARM_MAX_POST_SIZE);
            *in_size_ = 0;
            return NULL;
        }
    } else {
        in_size = WEBGFFARM_MAX_POST_SIZE;
    }

    bbin = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    rv = ap_get_brigade(r->input_filters, bbin, AP_MODE_READBYTES, APR_BLOCK_READ, in_size);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "[parse_form_from_POST] ap_get_brigade returns some error");
        return NULL;
    }
    bbin_size = in_size;
    buf = apr_palloc(r->pool, bbin_size);
    rv = apr_brigade_flatten(bbin, buf, &bbin_size);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "[parse_form_from_POST] apr_brigade_flatten returns some error");
        return NULL;
    }
    apr_brigade_destroy(bbin);
    *in_size_ = bbin_size;

    if (in_size != bbin_size) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "[parse_form_from_POST] in_size is incorrect(in: %d, out:%d)", in_size, (int) bbin_size);
    }
    return buf;
}

static int util_read(request_rec *r, char **rbuf, apr_off_t *size) {
    int rc = OK;
    *size = 0;
    if ((rc = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR))) {
        return (rc);
    }

    if (ap_should_client_block(r)) {
        char argsbuffer[WEBGFARM_BUFFER_SIZE];
        apr_off_t rsize, len_read, rpos = 0;

        apr_off_t length = r->remaining;

        *rbuf = (char *) apr_pcalloc(r->pool, (apr_size_t) (length + 1));
        *size = length;
        while ((len_read = ap_get_client_block(r, argsbuffer, sizeof (argsbuffer))) > 0) {
            if ((rpos + len_read) > length) {
                rsize = length - rpos;
            } else {
                rsize = len_read;
            }

            memcpy((char *) *rbuf + rpos, argsbuffer, (size_t) rsize);
            rpos += rsize;
        }
    }
    return (rc);
}

char *webgfarm_api_v1_getfilepath(request_rec *r) {
    webgfarm_config *wconfig = ap_get_module_config(r->server->module_config, &webgfarm_module);
    return r->uri + wconfig->basepathlen - 1;
}

int webgfarm_api_v1_read_file(request_rec *r) {
    // get filepath from request
    char *filepath = webgfarm_api_v1_getfilepath(r);

    if (filepath == NULL || strlen(filepath) == 0) {
        return HTTP_FORBIDDEN;
    }

    webgfarm_config *wconfig = ap_get_module_config(r->server->module_config, &webgfarm_module);

    gfarm_error_t gerr;
    GFS_File gfs_file;

    if (wconfig->read_redirect) {
        //        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "[read] read_redirect is on.");

        char *redirect_url = apr_palloc(r->pool, sizeof (char)*WEBGFARM_BUFFER_SIZE);

        const char *port;

        int available_nhosts;
        struct gfarm_host_sched_info *available_hosts;
        gerr = gfarm_schedule_hosts_domain_by_file(filepath, GFARM_FILE_RDONLY, "", &available_nhosts, &available_hosts);
        if (gerr == GFARM_ERR_NO_ERROR) {
            //            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "[read] gfarm_schedule_hosts_domain_by_file() has no error.");
            int *ports;
            char **hosts;
            int nhosts = available_nhosts;
            int i;
            GFARM_MALLOC_ARRAY(hosts, available_nhosts);
            GFARM_MALLOC_ARRAY(ports, available_nhosts);
            gerr = gfarm_schedule_hosts_acyclic(filepath, available_nhosts, available_hosts, &nhosts, hosts, ports);

            if (nhosts > 0 && gerr == GFARM_ERR_NO_ERROR) {
                //                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "[read] gfarm_schedule_hosts_acyclic() has no error.");
                for (i = 0; i < nhosts; i++) {
                    port = apr_table_get(wconfig->hosts, hosts[i]);
                    if (port != NULL) {
                        if (strcmp(wconfig->localhost, hosts[i]) != 0) {
                            if (wconfig->ssl) {
                                snprintf(redirect_url, WEBGFARM_BUFFER_SIZE, "https://%s:%s%s", hosts[i], port, r->uri);
                            } else {
                                snprintf(redirect_url, WEBGFARM_BUFFER_SIZE, "http://%s:%s%s", hosts[i], port, r->uri);
                            }
                            apr_table_set(r->headers_out, "Location", redirect_url);
                            free(ports);
                            free(hosts);
                            return HTTP_TEMPORARY_REDIRECT;
                        } else {
                            break;
                        }
                    }
                }
            }

            free(ports);
            free(hosts);
        } else if (gerr != GFARM_ERR_NO_SUCH_FILE_OR_DIRECTORY) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "gfarm_schedule_hosts_domain_by_file can not get the hosts of the file(%s) with error: %s", filepath, gfarm_error_string(gerr));
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    // open
    gerr = gfs_pio_open(filepath, GFARM_FILE_RDONLY, &gfs_file);
    if (gerr != GFARM_ERR_NO_ERROR) {
        switch (gerr) {
            case GFARM_ERR_NO_SUCH_FILE_OR_DIRECTORY:
                return HTTP_NOT_FOUND;
                break;
            case GFARM_ERR_PERMISSION_DENIED:
                return HTTP_FORBIDDEN;
                break;
                //FIXEME: Support more error;
            default:
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "gfs_pio_open can not open the file(%s) with error: %s", filepath, gfarm_error_string(gerr));
                return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    // get stat
    struct gfs_stat gs;
    gerr = gfs_pio_stat(gfs_file, &gs);
    if (gerr != GFARM_ERR_NO_ERROR) {
        gfs_pio_close(gfs_file);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "gfs_pio_stat can not get the stat of the file(%s) with error: %s", filepath, gfarm_error_string(gerr));
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    char *stat_buffer = apr_palloc(r->pool, sizeof (char)*WEBGFARM_BUFFER_SIZE);
    snprintf(stat_buffer, WEBGFARM_BUFFER_SIZE, "%lu", gs.st_ino);
    apr_table_set(r->headers_out, "X-WEBGFARM-STAT-INO", stat_buffer);
    snprintf(stat_buffer, WEBGFARM_BUFFER_SIZE, "%lu", gs.st_gen);
    apr_table_set(r->headers_out, "X-WEBGFARM-STAT-GEN", stat_buffer);
    snprintf(stat_buffer, WEBGFARM_BUFFER_SIZE, "%o", gs.st_mode);
    apr_table_set(r->headers_out, "X-WEBGFARM-STAT-MODE", stat_buffer);
    snprintf(stat_buffer, WEBGFARM_BUFFER_SIZE, "%lu", gs.st_nlink);
    apr_table_set(r->headers_out, "X-WEBGFARM-STAT-NLINK", stat_buffer);
    apr_table_set(r->headers_out, "X-WEBGFARM-STAT-USER", gs.st_user);
    apr_table_set(r->headers_out, "X-WEBGFARM-STAT-GROUP", gs.st_group);
    snprintf(stat_buffer, WEBGFARM_BUFFER_SIZE, "%lu", gs.st_size);
    apr_table_set(r->headers_out, "X-WEBGFARM-STAT-SIZE", stat_buffer);
    snprintf(stat_buffer, WEBGFARM_BUFFER_SIZE, "%lu", gs.st_ncopy);
    apr_table_set(r->headers_out, "X-WEBGFARM-STAT-NCOPY", stat_buffer);

    //    gerr == GFARM_ERR_NO_ERROR
    //read and puts
    if (!r->header_only) {
        char *buf = apr_palloc(r->pool, sizeof (char)*WEBGFARM_BUFFER_SIZE);
        int read_size = 0;
        do {
            gerr = gfs_pio_read(gfs_file, buf, WEBGFARM_BUFFER_SIZE, &read_size);
            if (gerr != GFARM_ERR_NO_ERROR) {
                gerr = gfs_pio_close(gfs_file);
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "gfs_pio_read can not read the file(%s) with error: %s", filepath, gfarm_error_string(gerr));
                return HTTP_INTERNAL_SERVER_ERROR;
            } else {
                if (read_size != 0) {
                    ap_rwrite(buf, read_size, r);
                }
            }
        } while (gerr == GFARM_ERR_NO_ERROR && read_size != 0);
    }

    // close
    gerr = gfs_pio_close(gfs_file);
    if (gerr != GFARM_ERR_NO_ERROR) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "gfs_pio_close can not close the file(%s) with error: %s", filepath, gfarm_error_string(gerr));

        return HTTP_INTERNAL_SERVER_ERROR;
    } else {
        return OK;
    }
}

int webgfarm_api_v1_read_dir(request_rec *r) {
    char *filepath = webgfarm_api_v1_getfilepath(r);
    if (filepath == NULL || strlen(filepath) == 0) {
        return HTTP_FORBIDDEN;
    }

    gfarm_error_t gerr;
    GFS_DirPlus gfs_dirplus;
    // open dir
    gerr = gfs_opendirplus(filepath, &gfs_dirplus);
    if (gerr != GFARM_ERR_NO_ERROR) {
        switch (gerr) {
            case GFARM_ERR_NO_SUCH_FILE_OR_DIRECTORY:
                return HTTP_NOT_FOUND;
                break;
            case GFARM_ERR_PERMISSION_DENIED:
                return HTTP_FORBIDDEN;
                break;
                //FIXEME: Support more error;
            default:
                return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    // read dir
    struct gfs_dirent *dent;
    struct gfs_stat *st;

    gerr = gfs_readdirplus(gfs_dirplus, &dent, &st);
    while (dent != NULL) {
        if (gerr != GFARM_ERR_NO_ERROR) {
            gerr = gfs_closedirplus(gfs_dirplus);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        if (dent->d_type == GFS_DT_REG) {
            ap_rprintf(r, "%s\n", dent->d_name);
        } else if (dent->d_type == GFS_DT_DIR) {
            ap_rprintf(r, "%s/\n", dent->d_name);
        }

        gerr = gfs_readdirplus(gfs_dirplus, &dent, &st);
    }

    // close dir
    gerr = gfs_closedirplus(gfs_dirplus);
    if (gerr != GFARM_ERR_NO_ERROR) {
        return HTTP_INTERNAL_SERVER_ERROR;
    } else {
        return OK;
    }
}

int webgfarm_api_v1_create_dir(request_rec *r) {
    char *filepath = webgfarm_api_v1_getfilepath(r);

    if (filepath == NULL || strlen(filepath) == 0) {
        return HTTP_FORBIDDEN;
    }

    gfarm_error_t gerr;
    gerr = gfs_mkdir(filepath, 0777);
    if (gerr != GFARM_ERR_NO_ERROR) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "gfs_mkdir can not create a directory(%s) with error: %s", filepath, gfarm_error_string(gerr));
        return HTTP_INTERNAL_SERVER_ERROR;
    } else {
        return OK;
    }
}

int webgfarm_api_v1_write_to_file(request_rec *r) {

    // get filepath from request
    char *filepath = webgfarm_api_v1_getfilepath(r);

    if (filepath == NULL || strlen(filepath) == 0) {
        return HTTP_FORBIDDEN;
    }

    gfarm_error_t gerr;
    GFS_File gfs_file;


    webgfarm_config *wconfig = ap_get_module_config(r->server->module_config, &webgfarm_module);
    if (wconfig->write_redirect) {

        char *redirect_url = apr_palloc(r->pool, sizeof (char)*WEBGFARM_BUFFER_SIZE);
        const char *port;

        int available_nhosts;
        struct gfarm_host_sched_info *available_hosts;
        gerr = gfarm_schedule_hosts_domain_by_file(filepath, GFARM_FILE_RDONLY, "", &available_nhosts, &available_hosts);

        if (available_nhosts > 0) {
            if (gerr == GFARM_ERR_NO_ERROR) {
                int *ports;
                char **hosts;
                int nhosts = available_nhosts;
                int i;
                GFARM_MALLOC_ARRAY(hosts, available_nhosts);
                GFARM_MALLOC_ARRAY(ports, available_nhosts);
                gerr = gfarm_schedule_hosts_acyclic_to_write(filepath, available_nhosts, available_hosts, &nhosts, hosts, ports);

                if (nhosts > 0 && gerr == GFARM_ERR_NO_ERROR) {
                    for (i = 0; i < nhosts; i++) {
                        port = apr_table_get(wconfig->hosts, hosts[i]);
                        if (port != NULL) {
                            if (strcmp(wconfig->localhost, hosts[i]) != 0) {
                                if (wconfig->ssl) {
                                    snprintf(redirect_url, WEBGFARM_BUFFER_SIZE, "https://%s:%s%s", hosts[i], port, r->uri);
                                } else {
                                    snprintf(redirect_url, WEBGFARM_BUFFER_SIZE, "http://%s:%s%s", hosts[i], port, r->uri);
                                }
                                apr_table_set(r->headers_out, "Location", redirect_url);
                                free(ports);
                                free(hosts);
                                return HTTP_TEMPORARY_REDIRECT;
                            } else {
                                break;
                            }
                        }
                    }
                }

                free(ports);
                free(hosts);
            } else if (gerr != GFARM_ERR_NO_SUCH_FILE_OR_DIRECTORY) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "gfarm_schedule_hosts_domain_by_file can not get the hosts of the file(%s) with error: %s", filepath, gfarm_error_string(gerr));
                return HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }

    // open
    if (r->method_number == M_POST) {
        gerr = gfs_pio_open(filepath, GFARM_FILE_WRONLY | GFARM_FILE_APPEND, &gfs_file);
    } else if (r->method_number == M_PUT) {
        gerr = gfs_pio_open(filepath, GFARM_FILE_WRONLY | GFARM_FILE_TRUNC, &gfs_file);
        if (gerr == GFARM_ERR_NO_SUCH_FILE_OR_DIRECTORY) {
            gerr = gfs_pio_create(filepath, GFARM_FILE_WRONLY, 0644, &gfs_file);
        }
    } else {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (gerr != GFARM_ERR_NO_ERROR) {
        switch (gerr) {
            case GFARM_ERR_NO_SUCH_FILE_OR_DIRECTORY:
                return HTTP_NOT_FOUND;
                break;
            case GFARM_ERR_PERMISSION_DENIED:
                return HTTP_FORBIDDEN;
                break;
                //FIXEME: Support more error;
            default:
                return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    // get input body size;
    int in_size;
    const char *clen = apr_table_get(r->headers_in, "Content-Length");
    if (clen != NULL) {
        in_size = strtol(clen, NULL, 0);
        if (in_size >= WEBGFFARM_MAX_POST_SIZE) {
            gfs_pio_close(gfs_file);
            return HTTP_BAD_REQUEST;
        }
    } else {
        gfs_pio_close(gfs_file);
        return HTTP_BAD_REQUEST;
    }

    if (in_size != 0) {
        apr_off_t size = 0;
        char *buf;

        if (util_read(r, &buf, &size) != OK) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "[write] failed reading POST body");
            gfs_pio_close(gfs_file);
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        in_size = (int) size;

        if (buf == NULL) {
            return HTTP_BAD_REQUEST;
        }

        // write buffer
        int write_size;
        gerr = gfs_pio_write(gfs_file, buf, in_size, &write_size);
        if (gerr != GFARM_ERR_NO_ERROR) {
            if (in_size != write_size) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "[write] gfs_pio_write failure..(in: %d, out: %d)", (int) in_size, (int) write_size);
            }
            gerr = gfs_pio_close(gfs_file);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    // close
    gerr = gfs_pio_close(gfs_file);
    if (gerr != GFARM_ERR_NO_ERROR) {
        return HTTP_INTERNAL_SERVER_ERROR;
    } else {
        return OK;
    }

}

int webgfarm_api_v1_delete_file(request_rec *r) {
    // get filepath from request
    char *filepath = webgfarm_api_v1_getfilepath(r);

    gfarm_error_t gerr;

    if (isdir(filepath)) { // dir
        gerr = gfs_rmdir(filepath);
    } else { // file
        gerr = gfs_unlink(filepath);
    }

    if (gerr != GFARM_ERR_NO_ERROR) {
        switch (gerr) {
            case GFARM_ERR_NO_SUCH_FILE_OR_DIRECTORY:
                return HTTP_NOT_FOUND;
                break;
            case GFARM_ERR_PERMISSION_DENIED:
                return HTTP_FORBIDDEN;
                break;
                //FIXEME: Support more error;
            default:
                return HTTP_INTERNAL_SERVER_ERROR;
        }
    } else {
        return OK;
    }
}

int webgfarm_api_v1(request_rec *r) {
    apr_table_t *table;
    const char *rename;

    int ret = HTTP_INTERNAL_SERVER_ERROR;

    ap_args_to_table(r, &table);
    char *filepath = webgfarm_api_v1_getfilepath(r);
    switch (r->method_number) {
        case M_GET:
            // return payload and metadata
            if (isdir(filepath)) {
                ret = webgfarm_api_v1_read_dir(r);
            } else {
                ret = webgfarm_api_v1_read_file(r);
            }
            break;
        case M_PUT:
            rename = apr_table_get(table, "rename");
            if (rename) {
            } else {
                // overwrite the file
                if (isdir(filepath)) {
                    ret = webgfarm_api_v1_create_dir(r);
                } else {
                    ret = webgfarm_api_v1_write_to_file(r);
                }
            }
            break;
        case M_POST:
            // append the file
            ret = webgfarm_api_v1_write_to_file(r);
            break;
        case M_DELETE:
            // remove the file
            ret = webgfarm_api_v1_delete_file(r);
            break;
    }

    //    }
    return ret;
}

static int webgfarm_handler(request_rec *r) {

    webgfarm_config *wconfig = ap_get_module_config(r->server->module_config, &webgfarm_module);
    if (!wconfig->enabled) {
        return DECLINED;
    }
    if (wconfig->basepath == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "WebGfarm is enabled but WebGfarmBase is not set.");
        return DECLINED;
    }
    if (r->uri != NULL) {
        if (strncmp(r->uri, wconfig->basepath, wconfig->basepathlen) == 0) {
            return webgfarm_api_v1(r);
        } else {
            ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "WebGfarmBase: %s, URL: %s", wconfig->basepath, r->uri);
        }
    }
    return DECLINED;
}

static apr_status_t webgfarm_child_exit(void* data) {
    gfarm_error_t gerr = gfarm_terminate();
    server_rec *s = data;
    if (gerr != GFARM_ERR_NO_ERROR) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, "mod_webgfarm webgfarm_child_exit gfarm_terminate fail");
    }
    return APR_SUCCESS;
}

static void webgfarm_child_init(apr_pool_t *p, server_rec *s) {

    gfarm_error_t gerr = gfarm_initialize(NULL, NULL);
    if (gerr != GFARM_ERR_NO_ERROR) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, "mod_webgfarm webgfarm_child_init gfarm_initialize fail");
    }
    apr_pool_cleanup_register(p, s, webgfarm_child_exit, webgfarm_child_exit);
}

static void webgfarm_register_hooks(apr_pool_t *p) {

    ap_hook_child_init(webgfarm_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(webgfarm_handler, NULL, NULL, APR_HOOK_MIDDLE);

}

static const char *webgfarm_set_enable(cmd_parms *cmd, void *dummy, int arg) {
    webgfarm_config *wconfig = ap_get_module_config(cmd->server->module_config, &webgfarm_module);
    wconfig->enabled = arg;
    return NULL;
}

static const char *webgfarm_set_redirect_ssl(cmd_parms *cmd, void *dummy, int arg) {
    webgfarm_config *wconfig = ap_get_module_config(cmd->server->module_config, &webgfarm_module);
    wconfig->ssl = arg;
    return NULL;
}

static const char *webgfarm_set_read_redirect(cmd_parms *cmd, void *dummy, int arg) {
    webgfarm_config *wconfig = ap_get_module_config(cmd->server->module_config, &webgfarm_module);
    wconfig->read_redirect = arg;
    return NULL;
}

static const char *webgfarm_set_write_redirect(cmd_parms *cmd, void *dummy, int arg) {
    webgfarm_config *wconfig = ap_get_module_config(cmd->server->module_config, &webgfarm_module);
    wconfig->write_redirect = arg;
    return NULL;
}

static const char *webgfarm_set_redirect_to(cmd_parms *cmd, void *sconf_, const char *arg_) {
    webgfarm_config *wconfig = ap_get_module_config(cmd->server->module_config, &webgfarm_module);
    char *hostname, *port;
    char *arg = malloc(sizeof (char) * WEBGFARM_BUFFER_SIZE);
    strncpy(arg, arg_, WEBGFARM_BUFFER_SIZE);
    hostname = strtok(arg, ":");
    port = strtok(NULL, ":");
    apr_table_set(wconfig->hosts, hostname, port);

    return NULL;
}

static const char *webgfarm_set_localhostname(cmd_parms *cmd, void *dummy, const char *arg_) {
    webgfarm_config *wconfig = ap_get_module_config(cmd->server->module_config, &webgfarm_module);
    char *hostname, *port;
    char *arg = malloc(sizeof (char) * WEBGFARM_BUFFER_SIZE);
    strncpy(arg, arg_, WEBGFARM_BUFFER_SIZE);
    hostname = strtok(arg, ":");
    port = strtok(NULL, ":");
    apr_table_set(wconfig->hosts, hostname, port);
    wconfig->localhost = hostname;
    wconfig->localhostlen = strlen(hostname);

    return NULL;
}

static const char *webgfarm_set_basepath(cmd_parms *cmd, void *dummy, const char *arg) {
    webgfarm_config *wconfig = ap_get_module_config(cmd->server->module_config, &webgfarm_module);
    wconfig->basepath = arg;
    wconfig->basepathlen = strlen(arg);
    return NULL;
}

static const command_rec webgfarm_cmds[] = {
    AP_INIT_FLAG("webgfarm", webgfarm_set_enable, NULL, RSRC_CONF, "Run webgfarm on this host"),
    AP_INIT_TAKE1("webgfarmbase", webgfarm_set_basepath, NULL, RSRC_CONF, "Setting webgfarm BasePath"),
    AP_INIT_FLAG("webgfarmredirectSSL", webgfarm_set_redirect_ssl, NULL, RSRC_CONF, "SSL Redirect"),
    AP_INIT_FLAG("webgfarmreadredirect", webgfarm_set_read_redirect, NULL, RSRC_CONF, "Redirect Mode"),
    AP_INIT_FLAG("webgfarmwriteredirect", webgfarm_set_write_redirect, NULL, RSRC_CONF, "Redirect Mode"),
    AP_INIT_TAKE1("webgfarmlocalhostname", webgfarm_set_localhostname, NULL, RSRC_CONF, "Localhost name"),
    AP_INIT_ITERATE("webgfarmredirectto", webgfarm_set_redirect_to, NULL, RSRC_CONF, "Redirect To[hostname:port]"), {
        NULL
    }
};


AP_DECLARE_MODULE(webgfarm) = {
    STANDARD20_MODULE_STUFF,
    NULL, /* create per-dir    config structures */
    NULL, /* merge  per-dir    config structures */
    webgfarm_create_server_config, /* create per-server config structures */
    NULL, /* merge  per-server config structures */
    webgfarm_cmds, /* table of config file commands       */
    webgfarm_register_hooks
};

