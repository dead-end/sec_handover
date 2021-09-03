/*
 * MIT License
 *
 * Copyright (c) 2021 dead-end
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

#define SMALL_BUFFER_SIZE 256

/******************************************************************************
 * The function waits for a child process to change the state.
 *****************************************************************************/

static void wait_for_child(const char *id_parent, const pid_t pid_child, const char *id_child)
{
	int status;

	char prefix[SMALL_BUFFER_SIZE];
	snprintf(prefix, SMALL_BUFFER_SIZE, "Process: '%s' with: %d child: '%s' with: %d", id_parent, getpid(), id_child, pid_child);

	do
	{

		//
		// wait for the child process to have a state change
		//
		printf("%s - Waiting for state change\n", prefix);

		if (waitpid(pid_child, &status, 0) == -1)
		{
			fprintf(stderr, "%s - Waitpid failed: %s\n", prefix, strerror(errno));
			exit(EXIT_FAILURE);
		}

		//
		// if the child process has not terminated we call ptrace PTRACE_CONT
		//
		if (!WIFEXITED(status) && ptrace(PTRACE_CONT, pid_child, NULL, NULL) == -1)
		{
			fprintf(stderr, "%s - Calling ptrace with  PTRACE_CONT failed: %s\n", prefix, strerror(errno));
			exit(EXIT_FAILURE);
		}

		printf("%s - Successfully continued child\n", prefix);

	} while (!WIFEXITED(status));

	printf("%s - Child exited with status: %d\n", prefix, WEXITSTATUS(status));
}

/******************************************************************************
 * The program is a test program for the ptrace structure.
 *****************************************************************************/

int main()
{

	pid_t pid_child;

	printf("Main with pid : %d parent: %d\n", getpid(), getppid());

	//
	// fork the process
	//
	if ((pid_child = fork()) == -1)
	{
		fprintf(stderr, "Unable to fork a new process: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	//
	// child
	//
	if (pid_child == 0)
	{

		printf("Started 'child' with pid : %d\n", getpid());

		if (ptrace(PTRACE_TRACEME) == -1)
		{
			fprintf(stderr, "Unable to trace main: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}

		pid_t pid_child_child;

		//
		// fork the process
		//
		if ((pid_child_child = fork()) == -1)
		{
			fprintf(stderr, "Unable to fork a new process: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}

		//
		// child child
		//
		if (pid_child_child == 0)
		{

			for (int i = 0; i < 10; i++)
			{
				printf("Process: 'child-child' pid: %d is alive\n", getpid());
				sleep(2);
			}

			//
			// parent child
			//
		}
		else
		{
			wait_for_child("child", pid_child_child, "child-child");
		}

		printf("Process: 'child' exit\n");
		exit(EXIT_SUCCESS);

		//
		// parent (main)
		//
	}
	else
	{
		wait_for_child("main", pid_child, "child");
	}

	exit(EXIT_SUCCESS);
}
