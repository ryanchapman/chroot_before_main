/*
 * dchroot.c - A chroot that works with dynamic libraries outside the chroot
 *             Requires chroot_before_main.so to work
 *
 * Copyright (C) 2012 Ryan A. Chapman. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   1. Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *
 *   2. Redistributions in binary form must reproduce the above copyright notice,
 *      this list of conditions and the following disclaimer in the documentation
 *      and/or other materials provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * Ryan Chapman, ryan@rchapman.org
 * Fri May 11 22:31:05 MDT 2012
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int mysetenv(const char *name, const char *value, int overwrite)
{
	int rc;
	if((rc=setenv(name, value, overwrite)) != 0) {
		fprintf(stderr, "ERROR: setenv(\"%s\", \"%s\", %d): ", name, value, overwrite);
		perror("");
		exit(1);
	}
	return(rc);
}

int main(int argc, char *argv[], char *envp[])
{
	pid_t pid;
	int status;

	if((pid=fork()) == 0) {
		// child
		mysetenv("LD_AUDIT", PATH_TO_SO, 1);
		mysetenv("LD_PRELOAD", PATH_TO_SO, 1);
#ifdef DEBUG
		printf("LD_AUDIT=%s\n", getenv("LD_AUDIT"));
#endif
		if(argc >= 5) {
			char *argv0 = *argv++;    // dchroot
			char *argv1 = *argv++;    // dir to chroot to
			char *argv2 = *argv++;    // user to setuid() to after chroot
			char *argv3 = *argv++;    // group to setgid() to after chroot
			char *argv4 = *argv;      // command user wants to execute
			execvp(argv4, argv);
		} else {
			fprintf(stderr, "usage: dchroot <chroot_dir> <user> <group> <program_to_execute> <args...>\n");
			exit(1);
		}
	} else if(pid == -1) {
		perror("fork() failed");
	} else {
		wait(&status);
		return(status);
	}

}
