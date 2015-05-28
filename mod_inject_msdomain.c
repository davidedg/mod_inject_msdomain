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
 Configuration
 ==============================================================================
 */
static const char *domain;

const char * inject_msdomain_set_domain(cmd_parms *cmd, void *cfg, const char *arg)
{
	domain = arg;
    return NULL;
}

/*
 ==============================================================================
 Configuration TABLE
 ==============================================================================
 */
static const command_rec directives[] =
{
    AP_INIT_TAKE1(
	"InjectMSDomain" ,
	inject_msdomain_set_domain,
	NULL,
	RSRC_CONF,
	"MS Domain to inject in Basic Authorization Header"
	 ),

    {NULL}
};

/*
 ==============================================================================
 HOOK HANDLER of "ap_hook_fixups"
 ==============================================================================
 */

static int my_proxyfixups(request_rec *r)
{
	const char *t;
	const char *sent_pw;
	const char *check_header;
	char *user;
	char *d;
	const char *auth_line;
	char *AuthType = (PROXYREQ_PROXY == r->proxyreq) ? "Proxy-Authorization" : "Authorization";

	if (domain == NULL) {// return DECLINED; }
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0,r, "INJECT_MSDOMAIN: MISSING InjectMSDomain Directive");
		return DECLINED;
	}
	
    auth_line = apr_table_get(r->headers_in, AuthType);
	if (!auth_line) { return DECLINED; }		// No AUTH from client

	if (strcasecmp(ap_getword(r->pool, &auth_line, ' '), "Basic")) {
		return DECLINED; }			// Get Auth TYPE

	while (*auth_line == ' ' || *auth_line == '\t') {
		         auth_line++;			// Skip blanks
	}

	t = ap_pbase64decode(r->pool, auth_line);	// Decode text
	user = ap_getword_nulls (r->pool, &t, ':');	// Break apart
	sent_pw = t;					// User:Pwd


     if( user == NULL || *user == '\0' )
	{ return DECLINED; }				// No username


	d = strstr(user, "\\");
	if (d != NULL) { // "\username" or "DOMAIN\username" or "\"
		if ((d-user) > 1) { // "DOMAIN\username"
			return DECLINED;  // ignore if domain is already present
		} else { // d-user == 1 ==> "\username" (some Androids)
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0,r, "INJECT_MSDOMAIN: FIXING: %s to %s", user, user+1);
			user = user+1;
		}
	}
		
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0,r, "INJECT_MSDOMAIN: CONVERTING: %s to %s\\%s", user, domain, user);
	
	user = apr_pstrcat( r->pool, // INJECT MSDOMAIN IF NOT PRESENT
		domain,
		"\\",
		user,
		NULL);
	
	
	auth_line = apr_pstrcat( r->pool, 	// Create new Authorization Header:
	"Basic " , 			                // "Basic base64encore(domain\user:pass)"
	ap_pbase64encode( r->pool,
		 apr_pstrcat( r->pool,
			 user,
			 ":", 		
			 sent_pw , 	
			 NULL))
	, NULL);
	apr_table_set( r->headers_in , AuthType , auth_line );

    return OK;
}



static void inject_msdomain_register_hooks(apr_pool_t *p)
{
     ap_hook_fixups(my_proxyfixups, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA inject_msdomain_module = {
    STANDARD20_MODULE_STUFF, 
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    directives,            /* table of config file commands       */
    inject_msdomain_register_hooks  /* register hooks                      */
};