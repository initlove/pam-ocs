#ifndef __OCS_UTILS_H__
#define __OCS_UTILS_H__

#include <sys/stat.h>
#include <sys/types.h>

#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/_pam_macros.h>
#include <security/pam_ext.h>

#include <glib.h>

int	ocs_pam_create_user (pam_handle_t *pamh);
int	ocs_pam_mkhomedir (pam_handle_t *pamh);
gchar * get_mapped_homedir (gchar *full_name);
#endif
