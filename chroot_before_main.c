/*
 * Method to chroot after dynamic libraries are loaded by ld.so but
 * before main() is called
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
 * Compile with:
 *   gcc -shared -fomit-frame-pointer -fPIC chroot_before_main.c -o chroot_before_main.so
 *
 * Ryan Chapman, ryan@rchapman.org
 * Fri May 11 22:31:05 MDT 2012
 */
#include <grp.h>
#include <link.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

unsigned int la_version(unsigned int version)
{
	// any version of the auditing library is ok with us
	return version;
}

int field_size(FILE *f)
{
	int size=0;
	while(getc(f) != '\0')
		size++;
	return(size);
}

void *malloc_and_zero(size_t size)
{
	void *buf = malloc(size);
	memset(buf, 0, size);
	return(buf);
}

void get_field(FILE *f, char *buf, size_t size)
{
	int i=0, c;
	do {
		c = getc(f);
		buf[i++] = c;
	} while(c != '\0' && i != size); // call to malloc_and_zero allocates one extra char for the null
	getc(f); // move past the null
}

void la_preinit(uintptr_t *cookie)
{
	char path_to_cmdline[256], *chroot_dir, *user, *group;
	int i=0, c, chroot_dir_size, user_size, group_size;
	FILE *f;

	memset(path_to_cmdline, 0, 256);
	if(snprintf(path_to_cmdline, 256, "/proc/%d/cmdline", getppid()) >= 256) {
		fprintf(stderr, "Not enough space to copy /proc/%d/cmdline to buffer.  Only 255 characters are available.\n", getppid());
		exit(1);
	}

	if((f=fopen(path_to_cmdline, "r")) == NULL) {
		perror("fopen()");
		exit(1);
	}
	field_size(f);                 // skip past argv[0] in /proc/PPID/cmdline
	chroot_dir_size=field_size(f); // count size of argv[1] (dir to chroot to) in /proc/PPID/cmdline
	user_size=field_size(f);       // count size of argv[2] (user name)
	group_size=field_size(f);      // count size of argv[3] (group name)

	if(chroot_dir_size == 0 || user_size == 0 || group_size == 0) {
		fprintf(stderr, "usage: dchroot <chroot_dir> <user> <group> <program_to_execute> <args...>\n");
		exit(1);
	}

	chroot_dir=malloc_and_zero((chroot_dir_size+1) * sizeof(char));
	user=malloc_and_zero((user_size+1) * sizeof(char));
	group=malloc_and_zero((group_size+1) * sizeof(char));
	rewind(f);
	field_size(f);                 // skip past argv[0] in /proc/PPID/cmdline

	get_field(f, chroot_dir, chroot_dir_size);
	get_field(f, user, user_size);
	get_field(f, group, group_size);

	struct passwd *pwd = getpwnam(user);
	if(pwd == NULL) {
		fprintf(stderr, "User %s not found in /etc/passwd\n", user);
		exit(1);
	}

	struct group *grp = getgrnam(group);
	if(grp == NULL) {
		fprintf(stderr, "Group %s not found in /etc/group\n", group);
		exit(1);
	}

	if(chdir(chroot_dir) == -1) {
		fprintf(stderr, "chroot(\"%s\"): ", chroot_dir);
		perror("");
		exit(1);
	}
	if(chroot(chroot_dir) == -1) {
		fprintf(stderr, "chroot(\"%s\"): ", chroot_dir);
		perror("");
		exit(1);
	}
	if(chdir("/") == -1) {
		fprintf(stderr, "chroot(\"%s\"): ", chroot_dir);
		perror("");
		exit(1);
	}
	if(setgid(grp->gr_gid) == -1) {
		fprintf(stderr, "setgid(%d): ", grp->gr_gid);
		perror("");
		exit(1);
	}
	if(setuid(pwd->pw_uid) == -1) {
		fprintf(stderr, "setuid(%d): ", pwd->pw_uid);
		perror("");
		exit(1);
	}

#ifndef ENABLE_ROOT
	// ensure that privileges cannot be restored
	if(setreuid(-1, 0) == 0) {
		fprintf(stderr, "ERROR: could not drop root privileges appropriately.\n");
		exit(1);
	}
#endif
}

#ifndef ENABLE_CHROOT
// Override the chroot() function.  Because this library will be preloaded, this version
// will have precedence.  Of course, someone could preload their own in front of this one...
int chroot(const char *path)
{
	fprintf(stderr, "WARNING: chroot() not implemented\n");
}
#endif
