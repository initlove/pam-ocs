/*
 * Copyright (c) 2005, 2006 Thorsten Kukuk <kukuk@suse.de>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 255
#endif

#define PAM_SM_ACCOUNT
#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION

#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/_pam_macros.h>
#include <security/pam_ext.h>
#include "pam_ocs.h"
#if 1
#include <rest/rest-proxy.h>
#include <rest/rest-proxy-call.h>
#include <rest/rest-xml-parser.h>
#endif

int
write_message (pam_handle_t *pamh, int msg_style, char **value, const char *fmt)
{
	struct pam_message msg[1], *pmsg[1];
	struct pam_response *resp = NULL;
	struct pam_conv *conv;
	void *conv_void;
	int retval;

        
	pmsg[0] = &msg[0];
        msg[0].msg_style = msg_style;
        msg[0].msg = fmt;

	retval = pam_get_item (pamh, PAM_CONV, (const void **) &conv_void);
	conv = (struct pam_conv *) conv_void;
	if (retval == PAM_SUCCESS) {
		retval = conv->conv (1, (const struct pam_message **)pmsg,
	              &resp, conv->appdata_ptr);
        	if (retval != PAM_SUCCESS) {
	            	return retval;
		} else {
			*value = resp[0].resp;
			free (resp);
			return PAM_SUCCESS;
		}
        } else {
		return retval;
	}
}

static int
pam_echo (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_IGNORE;
}

#if 1
int
ocs_auth_info (RestProxyCall *call, gchar **msg)
{
	RestXmlParser *parser;
 	RestXmlNode *node, *child, *meta;
	const gchar *payload;
	goffset len;
	gint val;

	parser = rest_xml_parser_new ();
  	payload = rest_proxy_call_get_payload (call);
	len = rest_proxy_call_get_payload_length (call);
	node = rest_xml_parser_parse_from_data (parser, payload, len);

	GList *values, *l;
	gchar *status_code = NULL;
	gchar *status_msg = NULL;

	values = g_hash_table_get_values (node->children);
    	for (l = values; l; l = l->next) {
		child = (RestXmlNode *)l->data;
		if (strcmp (child->name, "meta") == 0) {
			meta = child;
			break;
		}
	}
	g_list_free (values);

	values = g_hash_table_get_values (meta->children);
	for (l = values; l; l = l->next) {
		child = (RestXmlNode *)l->data;
		if (strcmp (child->name, "statuscode") == 0) {
			status_code = child->content;
		} else if (strcmp (child->name, "message") == 0) {
			status_msg = child->content;
		}
	}
	g_list_free (values);

	if (status_code) {
		val = atoi (status_code);
	} else
		return -1;

	if (status_msg) {
		*msg = g_strdup (status_msg);
	}

	return val;
}
#endif

void
prompt_info (pam_handle_t *pamh)
{
	gchar *user = NULL;
	gchar *password = NULL;
	gchar *server = NULL;
	int retval;

	retval = write_message(pamh, PAM_PROMPT_ECHO_ON, &server, "Server: ");
	if (retval != PAM_SUCCESS)
		return retval;

	retval = write_message(pamh, PAM_PROMPT_ECHO_ON, &user, "Login: ");
	if (retval != PAM_SUCCESS)
		return retval;

	retval = write_message(pamh, PAM_PROMPT_ECHO_OFF, &password, "Password: ");
	if (retval != PAM_SUCCESS)
		return retval;

	printf ("server %s, user %s password %s\n", server, user, password); 
	return PAM_SUCCESS;
}

int
pam_sm_authenticate (pam_handle_t *pamh, int flags, int argc,
                     const char **argv)
{
	prompt_info (pamh);
	const void *user;
	pam_get_item(pamh, PAM_USER, &user);
#if 1
	g_type_init();

        RestProxy *proxy;
        RestProxyCall *call;
	GError *error = NULL;
	gchar *uri = "http://localhost:3000";
        proxy = rest_proxy_new (uri, FALSE);
        call = rest_proxy_new_call (proxy);
	rest_proxy_call_add_params (call, "login", "dliang",
				"password", "novell123", NULL);
	rest_proxy_call_set_method (call, "POST");
	rest_proxy_call_set_function (call, "person/check");

 	if (!rest_proxy_call_sync (call, &error)) {
		g_error ("Cannot shout: %s", error->message);
		g_error_free (error);
		return PAM_AUTHINFO_UNAVAIL;
	} 

	gchar *msg = NULL;
	gint val = ocs_auth_info (call, &msg);

	printf ("val %d\n", val);
	if (msg) {
		printf ("msg %s\n", msg);
		g_free (msg);
	}
#endif
	return PAM_SUCCESS;
}

int
pam_sm_setcred (pam_handle_t *pamh UNUSED, int flags UNUSED,
		int argc UNUSED, const char **argv UNUSED)
{
  return PAM_IGNORE;
}

int
pam_sm_acct_mgmt (pam_handle_t *pamh, int flags, int argc,
		  const char **argv)
{
  return pam_echo (pamh, flags, argc, argv);
}

int
pam_sm_open_session (pam_handle_t *pamh, int flags, int argc,
		     const char **argv)
{
  return pam_echo (pamh, flags, argc, argv);
}

int
pam_sm_close_session (pam_handle_t *pamh UNUSED, int flags UNUSED,
		      int argc UNUSED, const char **argv UNUSED)
{
  return PAM_IGNORE;
}

int
pam_sm_chauthtok (pam_handle_t *pamh, int flags, int argc,
		  const char **argv)
{
  if (flags & PAM_PRELIM_CHECK)
    return pam_echo (pamh, flags, argc, argv);
  else
    return PAM_IGNORE;
}

#if PAM_STATIC
/* static module data */

struct pam_module _pam_ocs_modstruct = {
  "pam_ocs",
  pam_sm_authenticate,
  pam_sm_setcred,
  pam_sm_acct_mgmt,
  pam_sm_open_session,
  pam_sm_close_session,
  pam_sm_chauthtok,
};

#endif
