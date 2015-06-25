#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "http_log.h"  
#include "ap_hooks.h"
#include "mod_proxy.h"

// inject_msdomain.load:
//		LoadModule inject_msdomain_module /usr/lib/apache2/modules/mod_inject_msdomain.so
// apache conf:
// InjectMSDomain DOMAIN

/*
 ==============================================================================
    Configuration Structure
 ==============================================================================
 */

typedef struct {
	char *domain;
} inject_msdomain_config;


/*
 ==============================================================================
    Function Prototypes
 ==============================================================================
 */

static int    my_proxyfixups(request_rec *r);
static void* inject_msdomain_create_srv_conf(apr_pool_t* pool, server_rec* svr);
static void* inject_msdomain_create_dir_conf(apr_pool_t* pool, char* context);
static void   inject_msdomain_register_hooks(apr_pool_t *p);


/*
 ==============================================================================
    Configuration Table
 ==============================================================================
 */

static const command_rec directives[] =
{
	AP_INIT_TAKE1(
	"InjectMSDomain",
	ap_set_string_slot,
	(void*)APR_OFFSETOF(inject_msdomain_config, domain),
	OR_ALL,
	"MS Domain to inject in Basic Authorization Header"
	 ),

    {NULL}
};


/*
 ==============================================================================
    Module Name Tag
 ==============================================================================
 */

module AP_MODULE_DECLARE_DATA inject_msdomain_module = {
    STANDARD20_MODULE_STUFF,
    inject_msdomain_create_dir_conf,    /* create per-dir    config structures */
    NULL,                               /* merge  per-dir    config structures */
    inject_msdomain_create_srv_conf,    /* create per-server config structures */
    NULL,                               /* merge  per-server config structures */
    directives,                         /* table of config file commands       */
    inject_msdomain_register_hooks      /* register hooks                      */
};

/*
 =======================================================================================================================
    Hook registration
 =======================================================================================================================
 */

static void inject_msdomain_register_hooks(apr_pool_t *p)
{
     ap_hook_fixups(my_proxyfixups, NULL, NULL, APR_HOOK_MIDDLE);
}


/*
 =======================================================================================================================
    Configuration Functions
 =======================================================================================================================
 */

static void* inject_msdomain_create_srv_conf(apr_pool_t* pool, server_rec* svr) {
  inject_msdomain_config* s = apr_pcalloc(pool, sizeof(inject_msdomain_config));
  s->domain = NULL;
  return s ;
}

static void* inject_msdomain_create_dir_conf(apr_pool_t* pool, char* context) {
  inject_msdomain_config* d = apr_pcalloc(pool, sizeof(inject_msdomain_config));
  d->domain = NULL;
  return d ;
}


/*
 ==============================================================================
 HOOK HANDLER of "ap_hook_fixups"
 ==============================================================================
 */

static int my_proxyfixups(request_rec *r)
{
	const static char *AuthType = "Authorization";
	const char *t;
	const char *sent_pw;
	char *user;
	char *d;
	const char *auth_line;
	
	inject_msdomain_config *config = (inject_msdomain_config*) ap_get_module_config(r->per_dir_config, &inject_msdomain_module);

	if (config->domain == NULL) { return DECLINED; } // InjectMSDomain is empty
	
    auth_line = apr_table_get(r->headers_in, AuthType);
	if (!auth_line) { return DECLINED; }		// No AUTH sent from client

	if (strcasecmp(ap_getword(r->pool, &auth_line, ' '), "Basic")) {
		return DECLINED; }			// Get Auth TYPE

	while (*auth_line == ' ' || *auth_line == '\t') {
		         auth_line++;			// Skip blanks
	}

	t = ap_pbase64decode(r->pool, auth_line);	// Decode BASE64 Authorization Header
	user = ap_getword_nulls (r->pool, &t, ':');	// Break apart
	sent_pw = t;					// User:Pwd


    if( user == NULL || *user == '\0' ) { return DECLINED; } // No username


	d = strstr(user, "@");  // Username in UPN format (user@domain)
	if ( d != NULL)	{
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "INJECT_MSDOMAIN: Username in UPN format: %s", user);
		return DECLINED;
	}

	
	d = strstr(user, "\\");
	if (d != NULL) { // "\username" or "DOMAIN\username" or "\"
		if ((d-user) > 1) { // "DOMAIN\username"
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "INJECT_MSDOMAIN: Domain already present: %s", user);
			return DECLINED;  // ignore if domain is already present
		} else { // d-user == 1 ==> "\username" (some Androids)
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "INJECT_MSDOMAIN: FIXING: %s to %s", user, user+1);
			user = user+1;
		}
	}
		
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "INJECT_MSDOMAIN: CONVERTING: %s to %s\\%s", user, config->domain, user);
	
	auth_line = apr_pstrcat( r->pool,	// Create new Authorization Header:
	"Basic ",							// "Basic base64encode(domain\user:pass)"
	ap_pbase64encode( r->pool,
		 apr_pstrcat( r->pool,
			config->domain,				// INJECT MSDOMAIN
			"\\",
			user,
			":", 		
			sent_pw, 	
			NULL))
	, NULL);
	
	apr_table_set( r->headers_in , AuthType , auth_line );

    return OK;
}

