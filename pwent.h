/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/pwent.h 586 2013-01-19 10:32:53Z pk@CHALMERS.SE $ */

/* pwent.h - Password entry header file */

/* These routines write and read records from a password database,
 named "passdb" in the current directory.

 The 'mygetpwnam' routine takes as argument a username, and returns
 NULL on failure to find it in the database, or a pointer to static
 storage if found. This storage will be overwritten on the next
 call.

 The 'mysetpwent' routine takes a name, and a struct 'mypwent', and
 replaces the data pertaining to 'name' in the database with the
 supplied struct. It returns 0 on success, -1 on failure to replace
 the record.

 The database has free form records, the length of which must not
 exceed 79 characters, the fields are separated by ':', much like
 the passwd database. The fields are:
 name:uid:passwd:salt:no_of_failed_attempts:password_age respectively.

 Note the separate 'salt' field, to simplify some of non-obligatory
 assignments, it is of course entirely possible, not to use this
 field, but instead to include the salt in the password field, in
 similarity with the passwd database.  */

/* Usage: copy the files to your own working directory, and
 use; #include "pwent.h"   to include it. */

#ifndef PWENT_H
#define PWENT_H

/* Names of password files. */
#define MYPWENT_FILENAME     "passdb"
#define MYPWENT_TMP_FILENAME "passdb.tmp"

typedef struct {
	char *pwname; /* Username */
	int uid; /* User id */
	char *passwd; /* Password */
	char *passwd_salt; /* Make dictionary attack harder */
	int pwfailed; /* No. of failed attempts */
	int pwage; /* Age of password in no of logins */
} mypwent;

mypwent *mygetpwnam(char *name); /* Find entry matching username */
int mysetpwent(char *name, mypwent *pw); /* Set entry based on uid */

#endif
