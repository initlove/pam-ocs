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

#include "utils.h"

int
write_message (pam_handle_t *pamh, int msg_style, char **value, const char *fmt)
{
	struct pam_message msg[1], *pmsg[1];
	struct pam_response *resp = NULL;
	struct pam_conv *conv;
	void *conv_void;
	int retval;

system("echo 'write_message' | tee -a /tmp/ocs_log");        
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
			if (resp[0].resp)
				*value = resp[0].resp;
			free (resp);
			return PAM_SUCCESS;
		}
        } else {
		return retval;
	}
}

int
ocs_auth_info (RestProxyCall *call, gchar **msg)
{
	RestXmlParser *parser;
 	RestXmlNode *node, *child, *meta;
	const gchar *payload;
	goffset len;
	gint val;

system("echo 'ocs_auth_info' | tee -a /tmp/ocs_log");        
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

int
prompt_info (pam_handle_t *pamh)
{
system("echo 'prompt_info' | tee -a /tmp/ocs_log");        
        RestProxy *proxy = NULL;
        RestProxyCall *call = NULL;
	GError *error = NULL;
	gchar *uri;
	gchar *user = NULL;
	gchar *password = NULL;
	gchar *server = NULL;
	gchar *msg = NULL;
	int retval;
#if 0
	retval = write_message (pamh, PAM_PROMPT_ECHO_ON, &server, "Server: ");
	if (retval != PAM_SUCCESS)
		goto out;
#endif
//TODO: uri should be the definitly url, seems bug of soup or rest
//	I set it to my local server .. 
	uri = (const gchar *) server;
	uri = "http://127.0.0.1:3000";
        proxy = rest_proxy_new (uri, FALSE);
        call = rest_proxy_new_call (proxy);
	rest_proxy_call_set_function (call, "config");

 	if (!rest_proxy_call_sync (call, &error)) {
		write_message (pamh, PAM_ERROR_MSG, NULL, error->message);
		g_error_free (error);
		retval = PAM_AUTHINFO_UNAVAIL;
		goto out;
	} 

	const void *void_str = NULL;

	if ((pam_get_item (pamh, PAM_USER, &void_str) == PAM_SUCCESS) && void_str) {
		user = g_strdup (void_str);
	} else {	
		retval = write_message (pamh, PAM_PROMPT_ECHO_ON, &user, "OCS Login: ");
		if (retval != PAM_SUCCESS)
			goto out;
		else {
			gchar *new_user = g_strdup (user);
	//		gchar *new_user = g_strdup_printf ("%s@%s", user, uri);
			pam_set_item (pamh, PAM_USER, (const void *)new_user);
			g_free (new_user);
		}
	}

	void_str = NULL;
	if ((pam_get_item (pamh, PAM_AUTHTOK, &void_str) == PAM_SUCCESS) && void_str){
		password = g_strdup (void_str);
	} else {
		retval = write_message (pamh, PAM_PROMPT_ECHO_OFF, &password, "OCS Password: ");
		if (retval != PAM_SUCCESS)
			goto out;
		else
			pam_set_item (pamh, PAM_AUTHTOK, (const void *)password);
	}

	rest_proxy_call_add_params (call, 
				"login", user,
				"password", password, 
				NULL);
	rest_proxy_call_set_method (call, "POST");
	rest_proxy_call_set_function (call, "person/check");

 	if (!rest_proxy_call_sync (call, &error)) {
		retval = write_message (pamh, PAM_ERROR_MSG, NULL, error->message);
		g_error_free (error);
		retval = PAM_AUTHINFO_UNAVAIL;
		goto out;
	} 

	gint val = ocs_auth_info (call, &msg);
	if (val == 100) {
		retval = PAM_SUCCESS;
	} else {
		retval = write_message (pamh, PAM_ERROR_MSG, NULL, msg);
		retval = PAM_AUTH_ERR;
	}

out:
	if (user)
		g_free (user);
	if (password)
		g_free (password);
	if (server)
		g_free (server);
	if (msg)
		g_free (msg);

	if (call)
		g_object_unref (call);
	if (proxy)
		g_object_unref (proxy);

	return retval;
}

int
pam_sm_authenticate (pam_handle_t *pamh, int flags, int argc,
                     const char **argv)
{	
	g_type_init();

system("echo 'sm_auth' | tee -a /tmp/ocs_log");        
	int res = prompt_info (pamh);

	if (res == PAM_SUCCESS) {
		return ocs_pam_create_user (pamh);
	} else
		return res;
}

int
pam_sm_setcred (pam_handle_t *pamh UNUSED, int flags UNUSED,
		int argc UNUSED, const char **argv UNUSED)
{
  return PAM_SUCCESS;
}

int
pam_sm_acct_mgmt (pam_handle_t *pamh, int flags, int argc,
		  const char **argv)
{
  return PAM_SUCCESS;
}

int
pam_sm_open_session (pam_handle_t *pamh, int flags, int argc,
		     const char **argv)
{
system("echo 'sm_open session' | tee -a /tmp/ocs_log");
	int res;
	gchar *full_name = NULL;
	gchar *dir;

	res = ocs_pam_mkhomedir (pamh);

	if (res != PAM_SUCCESS)
		return res;
        pam_get_item(pamh, PAM_USER, &full_name);
	dir = get_mapped_homedir (full_name);
	gchar *cmd;

	cmd = g_strdup_printf ("fuse_ocs %s", dir);
gchar *tmp;
tmp = g_strdup_printf ("echo '%s' | tee -a /tmp/ocs_log", cmd);
system (tmp);
g_free (tmp);
	system (cmd);
	g_free (cmd);
	g_free (dir);

	return PAM_SUCCESS;
}

int
pam_sm_close_session (pam_handle_t *pamh UNUSED, int flags UNUSED,
		      int argc UNUSED, const char **argv UNUSED)
{
  return PAM_SUCCESS;
}

int
pam_sm_chauthtok (pam_handle_t *pamh, int flags, int argc,
		  const char **argv)
{
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
