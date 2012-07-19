#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/_pam_macros.h>
#include <security/pam_ext.h>

#include "utils.h"

gchar *
get_mapped_username (gchar *full_name)
{
	//TMP
	return g_strdup_printf ("123456");
}

gint 
get_mapped_uid (gchar *full_name)
{
	return 1234;
}

gint
get_mapped_gid (gchar *full_name)
{
	return 1234;
}

gchar *
get_mapped_homedir (gchar *full_name)
{
	return g_build_filename ("/home", full_name, NULL);
}

int
ocs_pam_create_user (pam_handle_t *pamh)
{
	/*FIXME: allocate the session user or perminate user */
	gchar *full_name = NULL;
	if (pam_get_item (pamh, PAM_USER, &full_name) != PAM_SUCCESS)
		return PAM_USER_UNKNOWN;

	gint uid = get_mapped_uid (full_name);
	gint gid = get_mapped_gid (full_name);
	gchar *dir;
	gchar *username;

	dir = get_mapped_homedir (full_name);
	username = get_mapped_homedir (full_name);

	gchar *cmd = g_strdup_printf ("useradd -c %s -d %s -u %d -g %d",
			full_name, dir, uid, gid, username);
	system (cmd);

	g_free (cmd);
	g_free (dir);
	g_free (username);
	g_free (full_name);

	return PAM_SUCCESS;
}

int
pam_create_homedir (pam_handle_t *pamh,
 			const char *dirname,
			mode_t mode)
{
	struct stat sbuf;

	if (stat(dirname, &sbuf) == 0) {
		return PAM_SUCCESS;
	}

	if (mkdir(dirname, mode) != 0) {
		 return PAM_PERM_DENIED;
	}

	return PAM_SUCCESS;
}

int
pam_chown_homedir(pam_handle_t *pamh,
			      const char *dirname,
			      uid_t uid,
			      gid_t gid)
{
	if (chown(dirname, uid, gid) != 0) {
		return PAM_PERM_DENIED;
	}

	return PAM_SUCCESS;
}

int
ocs_pam_mkhomedir(pam_handle_t *pamh)
{
	struct passwd *pwd = NULL;
	char *token = NULL;
	char *create_dir = NULL;
	char *user_dir = NULL;
	int ret;
	const char *username = NULL;
	gchar *mapped_username = NULL;
	mode_t mode = 0700;
	char *safe_ptr = NULL;
	char *p = NULL;

	/* Get the username */
	if (pam_get_item(pamh, PAM_USER, &username) != PAM_SUCCESS) {
		return PAM_USER_UNKNOWN;
	}
	
	mapped_username = get_mapped_username (username);
	pwd = getpwnam(mapped_username);
	g_free (mapped_username);
	if (pwd == NULL) {
		return PAM_USER_UNKNOWN;
	}

	ret = pam_create_homedir(pamh, pwd->pw_dir, 0700);

	return pam_chown_homedir(pamh, pwd->pw_dir,
				  pwd->pw_uid,
				  pwd->pw_gid);
}

