/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/pwent.c 584 2013-01-19 10:30:22Z pk@CHALMERS.SE $ */

/*
 A simple library for password databases.  Tobias Gedell 2007
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "pwent.h"

#define LINE_BUFFER_LENGTH  1000

/*
 Return pointer to password entry for specified user.
 
 Upon error, or if the user couldn't be found, NULL is returned.
 
 Note: The returned pointer points to static data.
 */
mypwent *mygetpwnam(char *name) {
	FILE *file;
	char buffer[LINE_BUFFER_LENGTH];

	static char pwname[LINE_BUFFER_LENGTH], passwd[LINE_BUFFER_LENGTH],
			passwd_salt[LINE_BUFFER_LENGTH];
	static mypwent ent = { pwname, 0, passwd, passwd_salt, 0, 0 };

	/* Open file, return NULL if it failed. */
	if ((file = fopen(MYPWENT_FILENAME, "rb")) == NULL)
		return NULL;

	/* Read each line, looking for the right entry. */
	while (fgets(buffer, sizeof(buffer), file) != NULL) {
		if (sscanf(buffer, "%[^:]:%d:%[^:]:%[^:]:%d:%d", ent.pwname, &ent.uid,
				ent.passwd, ent.passwd_salt, &ent.pwfailed, &ent.pwage) != 6)
			break;

		if (strcmp(pwname, name) == 0) {
			fclose(file);
			return &ent;
		}
	}

	fclose(file);

	return NULL;
}

/*
 Update password entry for user.
 
 Upon error, or if the user couldn't be found, -1 is returned,
 otherwise 0.
 */
int mysetpwent(char *name, mypwent *pw) {
	FILE *file;
	FILE *newfile;
	char buffer[LINE_BUFFER_LENGTH];
	char pwname[LINE_BUFFER_LENGTH];

	int status = -1;

	if ((file = fopen(MYPWENT_FILENAME, "rb")) == NULL)
		return -1;
	if ((newfile = fopen(MYPWENT_TMP_FILENAME, "wb")) == NULL) {
		fclose(file);
		return -1;
	}

	/* Read each line, looking for the right entry. */
	while (fgets(buffer, sizeof(buffer), file) != NULL) {
		if (sscanf(buffer, "%[^:]", pwname) != 1) {
			status = -1;
			break;
		}

		/* See if we found the entry to be updated. */
		if (strcmp(pwname, name) == 0) {
			if (snprintf(buffer, sizeof(buffer), "%s:%d:%s:%s:%d:%d\n",
					pw->pwname, pw->uid, pw->passwd, pw->passwd_salt,
					pw->pwfailed, pw->pwage) >= sizeof(buffer)) {
				status = -1;
				break;
			}

			status = 0;
		}

		if (fputs(buffer, newfile) < 0) {
			status = -1;
			break;
		}
	}

	fclose(newfile);
	fclose(file);

	/* Swap files if user successfully updated. */
	if (status == 0) {
		if (rename(MYPWENT_TMP_FILENAME, MYPWENT_FILENAME) != 0)
			status = -1;
	} else
		unlink(MYPWENT_TMP_FILENAME);

	return status;
}
