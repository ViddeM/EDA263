/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/makepass.c 584 2013-01-19 10:30:22Z pk@CHALMERS.SE $ */

/* makepass.c - Make a UNIX password */
/* compile with: gcc -o makepass makepass.c -lcrypt */
/* usage: "makepass 'salt'" */

#include <crypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include  <unistd.h>

int is_salt(char *salt) {
	char salts[] =
			"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";

	return strlen(salt) == 2 && strchr(salts, salt[0]) != 0
			&& strchr(salts, salt[1]) != 0 && salt[0] != '\0' && salt[1] != '\0';
}

int main(int argc, char *argv[]) {
	char *clear;
	char clear1[9];
	char *clear2;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s salt\n", argv[0]);
		return 1;
	}

	if (!is_salt(argv[1])) {
		fprintf(stderr, "(%s) is illegal salt!\n", argv[1]);
		return 2;
	}

	clear = getpass("Password: ");
	if (clear == NULL) {
		bzero(clear, 8);
		fprintf(stderr, "Not a tty!");
		return 3;
	}

	strncpy(clear1, clear, 8);
	bzero(clear, 8);

	clear2 = getpass("Re-enter password: ");
	if (clear2 == NULL) {
		bzero(clear2, 8);
		fprintf(stderr, "Not a tty!");
		return 3;
	}

	if (strcmp(clear1, clear2) != 0) {
		fprintf(stderr, "Sorry, passwords don't match.\n");
		bzero(clear1, 8);
		bzero(clear2, 8);
		return 4;
	}

	printf("Encrypted password: \"%s\"\n", crypt(clear1, argv[1]));
	bzero(clear1, 8);
	bzero(clear2, 8);

	return 0;
}

