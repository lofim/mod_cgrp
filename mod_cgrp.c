#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_script.h"
#include "http_connection.h"
#include "unixd.h"

#include "apr_strings.h"

#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <pwd.h>

#include <stdio.h>
#include <libcgroup.h>

#define MOD_ENABLED 1
#define MOD_DISABLED 0
#define ENTRY_VALID 1
#define ENTRY_INVALID 0

typedef struct {
    uid_t uid;
    char cgrp[NAME_MAX];
} uid_cgrp_entry_t;


typedef struct {
    int         enabled;            /* Enable or disable our module */
    apr_array_header_t *entries;    /* list of UID_to_CGRP entries */
    int         size;               /* Number of uid_to_cgrp entries */
} cgrp_server_config;


//prototypes
module AP_MODULE_DECLARE_DATA cgroup_module;

static void *cgrp_create_server_config(apr_pool_t *p, server_rec *s);
static void *cgrp_merge_server_config (apr_pool_t *p, void* base, void* new);
const char *cgrp_set_enabled(cmd_parms *cmd, void *cfg, const char *arg);
const char *cgrp_set_rule(cmd_parms *cmd, void *cfg, const char *arg1, const char* arg2);
static int check_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s);
static int validateEntry(uid_cgrp_entry_t *entry, server_rec *s);
static int cgrp_handler(const request_rec *r, apr_proc_t *newproc, ap_unix_identity_t *ugid );
static void register_hooks(apr_pool_t *pool);

/**/
static void *cgrp_create_server_config(apr_pool_t *p, server_rec *s)
{
    //allocate config object
    cgrp_server_config *conf =
    (cgrp_server_config *) apr_pcalloc(p, sizeof(cgrp_server_config));

    //alocate config entries array
    conf->entries = apr_array_make(p, 10, sizeof(uid_cgrp_entry_t));
    
    conf->enabled = MOD_DISABLED;
    conf->size = 0;

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, 
                "mod_cgrp-%s: %s - %d : %s", "create_config", "config created for server", conf->size, s->error_fname);

    return conf;
}

static void *cgrp_merge_server_config (apr_pool_t *p, void* base, void* new) {
    cgrp_server_config *merged = apr_pcalloc(p, sizeof(cgrp_server_config));
    cgrp_server_config *parent = (cgrp_server_config*)base;
    cgrp_server_config *child  = (cgrp_server_config*)new;
   
    if(!apr_is_empty_array(parent->entries) && parent->enabled) {
        child->entries = apr_array_append(p, parent->entries, child->entries);
        merged->size = parent->size + child->size;
    }
    merged->enabled = child->enabled;

    return (void*)merged;
}

/* Handler for the "cgrpEnabled" directive */
const char *cgrp_set_enabled(cmd_parms *cmd, void *cfg, const char *arg)
{
    server_rec *s = cmd->server;
    cgrp_server_config *conf = ap_get_module_config(s->module_config,
                                                 &cgroup_module);
    
    if(conf) {
        if(!strcasecmp(arg, "on")) {
            conf->enabled = MOD_ENABLED;
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, cmd->server, 
                    "mod_cgrp-%s: %s - %s", "set_enabled", "module is enabled", cmd->server->error_fname);
        } else { 
            conf->enabled = 0;
        }
    }
    
    return NULL;
}

/* Handler for the "cgrpRule directive"*/
const char *cgrp_set_rule(cmd_parms *cmd, void *cfg, const char *arg1, const char* arg2)
{
    server_rec *s = cmd->server;
    cgrp_server_config *conf = ap_get_module_config(s->module_config,
                                                 &cgroup_module);

    //module must be enabled to parse config entries
    if(!conf || !conf->enabled) {
        return NULL;
    }

    //uid_cgrp_entry_t *temp = APR_ARRAY_PUSH(conf->entries, uid_cgrp_entry_t);
    uid_cgrp_entry_t *temp = apr_array_push(conf->entries);

    if(temp == NULL) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, cmd->server, 
                "mod_cgrp-%s: %s", "set_rule", "cannot add conf entry");
    }
    
    temp->uid = atoi(arg1);
    apr_cpystrn(temp->cgrp, arg2, NAME_MAX);
         
    conf->size++;

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, cmd->server, 
        "mod_cgrp-%s: %s:%d %d - %s - %s", "set_rule", "added conf entry, new size is", temp->uid, conf->size, temp->cgrp, cmd->server->error_fname);

    return NULL;
}

static int check_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, 
                "mod_cgrp-%s: %s - %s", "check_config", "checking... getting conf", s->error_fname);

    cgrp_server_config *conf = ap_get_module_config(s->module_config,
                                                 &cgroup_module);

    if(!conf || !conf->enabled) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, 
            "mod_cgrp-%s: %s - %s", "check_config", "conf could not be aquired", s->error_fname);
        return OK;
    }

    if(cgroup_init() != 0) {
        conf->enabled = MOD_DISABLED;
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, 
            "mod_cgrp-%s: %s", "check_config", "cgroup init error");

        return OK;
    }

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, 
        "mod_cgrp-%s: %s - %s", "check_config", "cgroup initialized", s->error_fname);

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, 
        "mod_cgrp-%s: %s - %d - %s", "check_config", "checking size:", conf->size, s->error_fname);

    uid_cgrp_entry_t *entry;
    apr_array_header_t *filtered_entries = apr_array_make(p, 10, sizeof(uid_cgrp_entry_t));
    
    //filter out corrupted config entries
    while(!apr_is_empty_array(conf->entries)) {
        entry = apr_array_pop(conf->entries);
        conf->size--;
        
        //check validity of config entry
        if(validateEntry(entry, s)) {
            uid_cgrp_entry_t *temp = apr_array_push(filtered_entries);
            temp->uid = entry->uid;
            apr_cpystrn(temp->cgrp, entry->cgrp, NAME_MAX);
            conf->size++;    
        } else {
            //log that there is a problem in cofig directives
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, 
                "mod_cgrp-%s: %s - %s", "check_config", "entry not valid, probably an configuration error", s->error_fname);
        }
    }
    //assign the filltered list to config structure
    conf->entries = filtered_entries;

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, 
                "mod_cgrp-%s: %s - %d - %s", "check_config", "final size:", conf->size, s->error_fname);
        
    return OK;
}

static int validateEntry(uid_cgrp_entry_t *entry, server_rec *s) {  
    //test is user exists
    if(getpwuid(entry->uid) == NULL) {
        entry->uid = -1;
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, 
            "mod_cgrp-%s: %s: %d", "check_config", "UID does not exists in system", entry->uid);
        return ENTRY_INVALID;
    }

    //test id cgroup exists
    struct cgroup *temp_cgroup = cgroup_new_cgroup(entry->cgrp);

    if(cgroup_get_cgroup(temp_cgroup)) {
        entry->uid = -1;
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, 
            "mod_cgrp-%s: %s - %s - %s", "check_config", "cgroup fail retrieve data", entry->cgrp, s->error_fname);   

        cgroup_free(&temp_cgroup);
        return ENTRY_INVALID;
    }
    cgroup_free(&temp_cgroup);

    return ENTRY_VALID;
}

/* Main module handler */
static int cgrp_handler(const request_rec *r, apr_proc_t *newproc, ap_unix_identity_t *ugid)
{

    if(r->server->module_config == NULL) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "CGRP-handler error getting the module config");        
        return OK;
    }

    cgrp_server_config *conf = ap_get_module_config(r->server->module_config, &cgroup_module);
    
    if(!conf || !conf->enabled) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "CGRP-handler config NOT aquired....%s", r->server->error_fname);
        return OK;
    }

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "CGRP-handler config size = %d", conf->size);
    int i;
    
    for(i = 0; i < conf->size; i++) {
        uid_cgrp_entry_t* entry = &APR_ARRAY_IDX(conf->entries,i, uid_cgrp_entry_t);
        
        if(entry == NULL ) {
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "CGRP-handler entry: no entry");
            return OK;
        }

        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "CGRP-handler entry: %d-%s vs ident: %d", entry->uid, entry->cgrp, ugid->uid);
            
        if(entry->uid == ugid->uid) {
            struct cgroup *temp_cgroup = cgroup_new_cgroup(entry->cgrp);

           ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "CGRP-handler pid: %d  with uid: %d adding to cgroup: %s", entry->uid, newproc->pid ,entry->cgrp);     
            if(cgroup_get_cgroup(temp_cgroup) == 0) {    
                int ret = cgroup_attach_task_pid(temp_cgroup, newproc->pid);
                cgroup_free(&temp_cgroup);

                if(ret == 0) ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "CGRP-handler pid: %d  with uid: %d adding to cgroup: %s DONE", newproc->pid, entry->uid ,entry->cgrp);
                else ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "CGRP-handler pid: %d  with uid: %d adding to cgroup: %s FAIL", entry->uid, newproc->pid ,entry->cgrp);
                return OK;
            }
            cgroup_free(&temp_cgroup);
        }   
    }

    return OK;
}

static void register_hooks(apr_pool_t *pool)
{
    ap_hook_check_config(check_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_assign_proc_to_cgroup(cgrp_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec cgrp_directives[] =
{
    AP_INIT_TAKE1("cgrpEnabled", cgrp_set_enabled, NULL, RSRC_CONF, "Enable or disable mod_cgrp"),
    AP_INIT_TAKE2("cgrpRule", cgrp_set_rule, NULL, RSRC_CONF, "UID to Control Group rule"),
    { NULL }
};

//add configuration directives UID:CGRP
//add post configuration hook (test configuration semantics)
//finish cgrp_handler implementation using cgroup

module AP_MODULE_DECLARE_DATA   cgroup_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    cgrp_create_server_config, // per server handler
    NULL, //cgrp_merge_server_config,
    cgrp_directives,    // module directives
    register_hooks      // module main handler
};
