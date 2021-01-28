/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -std=gnu99 -Wall -g -o mylogin login_linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
#include "pwent.h"
/* Uncomment next line in step 2 */
/* #include "pwent.h" */

#define TRUE 1
#define FALSE 0
#define LENGTH 16

void sighandler() {

	/* add signalhandling routines here */
	/* see 'man 2 signal' */
}

int main(int argc, char *argv[]) {

	mypwent *passwddata;
	/* see pwent.h */

	char important1[LENGTH] = "**IMPORTANT 1**";

	char user[LENGTH];

	char important2[LENGTH] = "**IMPORTANT 2**";

	//char   *c_pass; //you might want to use this variable later...
	char prompt[] = "password: ";
	char *user_pass;
	char *crypt_user_pass;

	sighandler();

	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important1' before input of login name: %s\n",
				important1);
		printf("Value of variable 'important2' before input of login name: %s\n",
				important2);

		printf("login: ");
		fflush(NULL); /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */

		if (fgets(user, LENGTH, stdin) == NULL)
		    exit(0);

//        if (gets(user) == NULL)
//            exit(0);

        for (int i = 0; i < LENGTH; i++) {
            char c = user[i];
            if (c == 10) {
                // Replace newline with NULL
                user[i] = 0;
            }
        }


		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important 1' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important1);
		printf("Value of variable 'important 2' after input of login name: %*.*s\n",
		 		LENGTH - 1, LENGTH - 1, important2);

		user_pass = getpass(prompt);
		printf("PASSWORD: '%s'\n", user_pass);
//		passwddata = getpwnam(user);
        passwddata = mygetpwnam(user);

        crypt_user_pass = crypt(user_pass, passwddata->passwd_salt);

		if (passwddata != NULL && !strcmp(crypt_user_pass, passwddata->passwd)) {
			/* You have to encrypt user_pass for this to work */
			/* Don't forget to include the salt */

            printf(" You're in ! After %d tries\n", passwddata->pwfailed + 1);
            passwddata->pwfailed = 0;
            passwddata->pwage += 1;
            if (passwddata->pwage >= 10) {
                printf("Your password is old AF, please change now or be hacked. (-- Ye twat)\n");
            }
            mysetpwent(user, passwddata);

            /*  check UID, see setuid(2) */
            /*  start a shell, use execve(2) */

        } else {
            printf("Login Incorrect \n");
            passwddata->pwfailed += 1;
            mysetpwent(user, passwddata);
        }
	}
	return 0;
}