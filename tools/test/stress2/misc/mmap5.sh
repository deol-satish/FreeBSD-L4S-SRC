#!/bin/sh

#
# Copyright (c) 2013 EMC Corp.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

# Test scenario inspired by alc@
# "panic: vm_page_dirty: page is invalid!" seen.
# Fixed in r255396.

. ../default.cfg

dir=/tmp
odir=`pwd`
cd $dir
sed '1,/^EOF/d' < $odir/$0 > $dir/mmap5.c
mycc -o mmap5  -Wall -Wextra mmap5.c || exit 1
rm -f mmap5.c
cd $odir

cp /tmp/mmap5  /tmp/mmap5.inputfile
(cd ../testcases/swap; ./swap -t 1m -i 2) &
cp /tmp/mmap5 /tmp/mmap5.inputfile
/tmp/mmap5  /tmp/mmap5.inputfile
while killall -9 swap; do
	sleep .1
done > /dev/null 2>&1
wait
rm -f /tmp/mmap5  /tmp/mmap5.inputfile
exit

EOF
#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

const char *file;

void
test2(void)
{
	struct stat st;
	char *p;
	size_t len;
	int error, fd;

	if ((fd = open(file, O_RDWR)) == -1)
		err(1, "open %s", file);
	if ((error = fstat(fd, &st)) == -1)
		err(1, "stat(%s)", file);
	len = round_page(st.st_size);
	if ((p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED)
		err(1, "mmap");
	p[arc4random() % len] = 1;
	if (arc4random() % 100 < 50)
		if ((error = mlock(p, len)) == -1)
			err(1, "mlock");
	p[arc4random() % len] = 1;
	if (arc4random() % 100 < 50)
		if ((error = msync(p, len, MS_SYNC | MS_INVALIDATE)) == -1)
			if (errno != EBUSY)
				err(1, "msync");
	if (munmap(p, len) == -1)
		err(1, "unmap()");
	close(fd);
	_exit(0);

}

void
test(void)
{
	int i;

	for (i = 0; i < 3; i++)
		if (fork() == 0)
			test2();
	for (i = 0; i < 3; i++)
		wait(NULL);

	_exit(0);
}

int
main(int argc, char *argv[])
{
	time_t start;

	if (argc != 2)
		errx(1, "Usage: %s <file>", argv[0]);
	file = argv[1];

	start = time(NULL);
	while (time(NULL) - start < 120) {
		if (fork() == 0)
			test();
		wait(NULL);
	}

	return (0);
}
