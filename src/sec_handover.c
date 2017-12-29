/***************************************************************************
 * sec_handover.c
 *
 *  Created on: Aug 12, 2017
 *      Author: dead-end
 **************************************************************************/

#include <sh_generated_keys.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "sh_gcrypt.h"
#include "sh_utils.h"
#include "sh_hex.h"
#include "sh_commons.h"
#include "sh_start_data.h"

#include <termios.h>
#include <unistd.h>

#include <sys/ptrace.h>

#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>

#define ID_MAIN "main(tracer)"

#define ID_HAND_OVER "handover(tracer/tracee)"

#define ID_EXECV "execv(tracee)"

/***************************************************************************
 * The struct contains the parsed arguments.
 **************************************************************************/

typedef struct {

	//
	// The name of the unencrypted configuration file. In launch mode the
	// parameter should be NULL.
	//
	char *sign_file;

	//
	// The name of the encrypted configuration file. In sign mode the
	// parameter should be NULL.
	//
	char *launch_file;

	//
	// The output file for the sign mode. This will be the encrypted file.
	//
	char *out_file;

	//
	// A flag that indicated whether to read the password interactively or
	// to read the password from the configuration file. The later is only
	// recommended for test cases.
	//
	bool interactive_passwd;

} s_arguments;

/***************************************************************************
 * The function sets ulimit to 0 to avoid core dumps.
 **************************************************************************/

static bool avoid_coredumps() {
	struct rlimit struct_rlimit;

	struct_rlimit.rlim_cur = 0;
	struct_rlimit.rlim_max = 0;

	if (setrlimit(RLIMIT_CORE, &struct_rlimit) < 0) {
		print_error("avoid_coredumps() Setting ulimt to 0 failed: %s\n", strerror(errno));
		return false;
	}

	return true;
}

/***************************************************************************
 * The function reads a password from a stream. Echoing is switched off and
 * the tailing newline is removed.
 **************************************************************************/

static bool read_password(FILE *stream, char *password, const int size) {
	static struct termios actual, no_echo;

	//
	// get settings of the actual terminal
	//
	if (tcgetattr(fileno(stream), &actual) != 0) {
		print_error("read_password() Unable to get terminal attribute: %s\n", strerror(errno));
		return false;
	}

	//
	// copy the struct and switch off echoing
	//
	no_echo = actual;
	no_echo.c_lflag &= ~(ECHO);

	//
	// set this as the new terminal options
	//
	if (tcsetattr(fileno(stream), TCSANOW, &no_echo) != 0) {
		print_error("read_password() Unable to set terminal attribute: %s\n", strerror(errno));
		return false;
	}

	//
	// read the password from the stream
	//
	if (fgets(password, size, stdin) == NULL) {
		print_error_str("read_password() Empty password is not allowed!\n");
		return false;
	}

	//
	// replace \n with \0
	//
	password[strlen(password) - 1] = '\0';

	//
	// restore the old terminal settings
	//
	if (tcsetattr(fileno(stream), TCSANOW, &actual) != 0) {
		print_error("read_password() Unable to set terminal attribute: %s\n", strerror(errno));
		return false;
	}

	return true;
}

/***************************************************************************
 * The function twice prints a prompt and reads a password from the stream.
 * On success the password is duplicated and returned.
 **************************************************************************/

static bool read_checked_passwd(FILE *stream, char **passwd) {
	char line1[MAX_LINE];
	char line2[MAX_LINE];

	printf("Enter password:");
	if (!read_password(stdin, line1, MAX_LINE)) {
		print_error_str("read_checked_passwd() Unable to read password!\n");
		return false;
	}

	printf("\nReenter password:");
	if (!read_password(stdin, line2, MAX_LINE)) {
		print_error_str("read_checked_passwd() Unable to read password!\n");
		return false;
	}
	printf("\n");

	//
	// ensure that both passwords are the same.
	//
	if (strncmp(line1, line2, MAX_LINE) != 0) {
		print_error_str("read_checked_passwd() Passwords differ!\n");
		return false;
	}

	//
	// duplicate the password
	//
	*passwd = strdup(line1);
	if (passwd == NULL) {
		print_error_str("read_checked_passwd() Unable to allocate memory!\n");
		return false;
	}

	return true;
}

/***************************************************************************
 * The function creates a signed file from an unsigned file. The unsigned
 * file is unencrypted and contains the start data without the file hashes.
 * The password is optional. The method computes the hashes and writes the
 * start data to a file which is encryted.
 **************************************************************************/

static bool sign_file(const s_arguments *arguments) {
	bool result = false;

	//
	// create a start data structure
	//
	s_start_data *start_data = sh_start_data_create();
	if (start_data == NULL) {
		print_error_str("sign_file() Unable create start data!\n");
		goto CLEANUP;
	}

	//
	// read the password interactively, if configured
	//
	if (arguments->interactive_passwd) {
		if (!read_checked_passwd(stdin, &(start_data->passwd))) {
			print_error_str("sign_file() Unable read password from stdin!\n");
			goto CLEANUP;
		}
	}

	//
	// read the start data from the unencrypted file
	//
	if (!sh_start_data_read(arguments->sign_file, start_data, false)) {
		print_error_str("sign_file() Unable to read start data\n");
		goto CLEANUP;
	}

	//
	// compute the hashes and write the result to an encrypted file
	//
	if (!sh_start_data_compute_hashes(start_data, false)) {
		print_error_str("sign_file() Unable to compute hashes\n");
		goto CLEANUP;
	}

	if (!sh_start_data_write_encr(arguments->out_file, start_data)) {
		print_error_str("sign_file() Unable to encrypt start data\n");
		goto CLEANUP;
	}

	result = true;

	//
	// Cleanup allocated resources
	//
	CLEANUP:

	sh_start_data_free(start_data);

	return result;
}

/***************************************************************************
 * The function waits for a child process to exit. If the state of the child
 * changes ptrace has to be continued.
 **************************************************************************/

static bool wait_for_child(const char *id_parent, const pid_t pid_child, const char *id_child) {
	int status;

	char prefix[SMALL_BUFFER_SIZE];
	snprintf(prefix, SMALL_BUFFER_SIZE, "Process: '%s' with: %d child: '%s' with: %d", id_parent, getpid(), id_child, pid_child);

	do {

		//
		// wait for the child process to have a state change
		//
		print_debug("wait_for_child() %s - Waiting for state change\n", prefix);

		if (waitpid(pid_child, &status, 0) == -1) {
			print_error("wait_for_child() %s - Waitpid failed: %s\n", prefix, strerror(errno));
			goto HANDLE_ERROR;
		}

		//
		// if the child process has not terminated we call ptrace PTRACE_CONT
		//
		if (!WIFEXITED(status) && ptrace(PTRACE_CONT, pid_child, NULL, NULL) == -1) {
			print_error("wait_for_child() %s - Calling ptrace with  PTRACE_CONT failed: %s\n", prefix, strerror(errno));
			goto HANDLE_ERROR;
		}

		print_debug("wait_for_child() %s - Successfully continued child\n", prefix);

	} while (!WIFEXITED(status));

	print_debug("wait_for_child() %s - Child exited with status: %d\n", prefix, WEXITSTATUS(status));

	return true;

	//
	// On errors ensure to kill child (for security and fun)
	//
	HANDLE_ERROR:

	if (kill(pid_child, SIGKILL) == -1) {
		print_error("wait_for_child() %s - Killing child failed: %s\n", prefix, strerror(errno));
	}

	return false;
}

/*******************************************************************************
 * The function does a lot of the magic. It forks a child process and starts the
 * target program with execv. It creates a pipe form the parent to the child
 * which is used to hand over the password.
 ******************************************************************************/

static bool exec_program(const s_start_data *start_data) {
	int pipe_fd[2];
	pid_t pid;

	//
	// create an unidirectional pipe from the parent to the child
	//
	if (pipe(pipe_fd) < 0) {
		print_error("exec_program() Unable to create a pipe: %s", strerror(errno));
		return false;
	}

	//
	// fork the process
	//
	if ((pid = fork()) == -1) {
		print_error("exec_program() Unable to fork a new process: %s\n", strerror(errno));
		return false;
	}

	//
	// process the child
	//
	if (pid == 0) {
		print_debug("exec_program() Process: %s pid: %d was successfully forked\n",ID_EXECV , getpid());

		//
		// be ready to be traced
		//
		if (ptrace(PTRACE_TRACEME) == -1) {
			print_error("exec_program() Process: %s pid: %d - ptrace failed: %s\n", ID_EXECV, getpid(), strerror(errno));
			return false;
		}

		//
		// The child reads the password from the pipe and continue writing to stdout.
		// So the stdout of the pipe is useless.
		//
		if (close(pipe_fd[STDOUT_FILENO]) == -1) {
			print_error("exec_program() Unable to close file descriptor: %s\n", strerror(errno));
			return false;
		}

		//
		// copy the pipe stdin to stdin, so the child reads from the pipe by the stdin fd
		//
		if (dup2(pipe_fd[STDIN_FILENO], STDIN_FILENO) == -1) {
			print_error("exec_program() Unable to dup file descriptor: %s\n", strerror(errno));
			return false;
		}

		//
		// close the duplicated pipe stdin
		//
		if (close(pipe_fd[STDIN_FILENO]) == -1) {
			print_error("exec_program() Unable to close file descriptor: %s\n", strerror(errno));
			return false;
		}

		//
		// start the program
		//
		if (execv(start_data->path, start_data->argv) == -1) {
			print_error("exec_program() Unable to exec program: %s due to: %s\n", start_data->path, strerror(errno));
			return false;
		}

		//
		// if the execution of the program was sucessfull, this code will not be reached
		//
		print_error("exec_program() Process: %s pid: %d - execution of program: %s failed\n", ID_EXECV, getpid(), start_data->path);
		return false;

		//
		// process the parent
		//
	} else {
		print_debug("exec_program() Process: %s pid: %d successfully forked child: %s pid: %d\n",ID_HAND_OVER , getpid(), ID_EXECV, pid);

		//
		// the parent writes the password to the pipe, so stdin is useless
		//
		if (close(pipe_fd[STDIN_FILENO]) == -1) {
			print_error("exec_program() Unable to close file descriptor: %s\n", strerror(errno));
			return false;
		}

		//
		// open stdout to write the password to
		//
		FILE *pipe = fdopen(pipe_fd[STDOUT_FILENO], "w");
		if (pipe == NULL) {
			print_error("exec_program() Unable to open the pipe: %s\n", strerror(errno));
			return false;
		}

		//
		// write the password
		//
		if (fprintf(pipe, "%s\n", start_data->passwd) < 0) {
			print_error_str("exec_program() Unable to write the password to the pipe\n");
			return false;
		}

		//
		// close the pipe because there is nothing more to say
		//
		if (fclose(pipe) == -1) {
			print_error("exec_program() Unable to close the pipe: %s\n", strerror(errno));
			return false;
		}

		print_debug_str("exec_program() Password handed over!\n");

		//
		// wait for the child to exit
		//
		if (!wait_for_child(ID_HAND_OVER, pid, ID_EXECV)) {
			print_error("main() Unable to wait for child: %d\n", pid);
			return EXIT_FAILURE;
		}

		print_debug("main() Process: %s pid: %d finished!\n",ID_HAND_OVER , getpid());
	}

	return true;
}

/***************************************************************************
 * The function launches the target program. For this to do, the encrypted
 * configuration file (launch_file) is read, the hashes in the file are
 * checked and on success the program is executed.
 **************************************************************************/

static bool launch_program(const s_arguments *arguments) {
	bool result = false;

	//
	// create the structure for the start data
	//
	s_start_data *start_data = sh_start_data_create();
	if (start_data == NULL) {
		print_error_str("launch_program() Unable to allocate memory!\n");
		goto CLEANUP;
	}

	//
	// read the encrypted launch file and save the content in the start data
	// structure.
	//
	if (!sh_start_data_read_encr(arguments->launch_file, start_data)) {
		print_error("launch_program() Unable to read start data from file: %s\n", arguments->launch_file);
		goto CLEANUP;
	}

	//
	// check the hashes from the launch file with the actual hashes of the
	// files to see, whether a file has changed (which is a security risc).
	//
	if (!sh_start_data_compute_hashes(start_data, true)) {
		print_error("launch_program() Unable to compute hashes for launch file: %s\n", arguments->launch_file);
		goto CLEANUP;
	}

	//
	// if the hashes are ok we can start the target program.
	//
	if (!exec_program(start_data)) {
		print_error("launch_program() Unable to launch file: %s\n", arguments->launch_file);
		goto CLEANUP;
	}

	result = true;

	//
	// Cleanup allocated resources
	//
	CLEANUP:

	sh_start_data_free(start_data);

	return result;
}

/***************************************************************************
 * The function writes the program usage. It is called with an error flag.
 * Depending on the flag the stream (stdout / stderr) is selected. The
 * function contains an optional message (not NULL) that will be written.
 **************************************************************************/

static void print_usage(const bool has_error, const char* msg) {
	FILE *stream;
	int status;

	//
	// choose stdout / stderr depending on the error flag
	//
	if (has_error) {
		status = EXIT_FAILURE;
		stream = stderr;
	} else {
		status = EXIT_SUCCESS;
		stream = stdout;
	}

	//
	// if the function call contains a message it is written
	//
	if (msg != NULL) {
		if (has_error) {
			fprintf(stream, "ERROR - ");
		}
		fprintf(stream, "%s\n", msg);
	}

	//
	// print the usage information
	//
	fprintf(stream, "sec_handover [-n] -s FILE -o FILE\n");
	fprintf(stream, "sec_handover -l FILE\n");
	fprintf(stream, "\t -n      No interactive password. The password is read from the config file.\n");
	fprintf(stream, "\t -s FILE Sign config file \n");
	fprintf(stream, "\t -o FILE The signed config file \n");
	fprintf(stream, "\t -l FILE Launch program with config file\n");

	exit(status);
}

/***************************************************************************
 * The function parses the program args.
 **************************************************************************/

static bool process_args(const int argc, char * const argv[], s_arguments *arguments) {

	int index;
	int c;

	while ((c = getopt(argc, argv, "s:l:o:n")) != -1) {
		switch (c) {

		case 's':
			arguments->sign_file = optarg;
			print_debug("process_args() Found sign file: %s\n", arguments->sign_file);
			break;

		case 'l':
			arguments->launch_file = optarg;
			print_debug("process_args() Found launch file: %s\n", arguments->launch_file);
			break;

		case 'o':
			arguments->out_file = optarg;
			print_debug("process_args() Found out file: %s\n", arguments->out_file);
			break;

		case 'n':
			arguments->interactive_passwd = false;
			break;

		default:
			print_usage(true, NULL);
		}
	}

	//
	// The program has a sign and a launch mode, so one of the corresponding
	// files have to be set.
	//
	if (arguments->sign_file != NULL && arguments->launch_file != NULL) {
		print_usage(true, "Sign or launch");
	}

	//
	// Not both of the corresponding files have to be set.
	//
	if (arguments->sign_file == NULL && arguments->launch_file == NULL) {
		print_usage(true, "Please select '-s FILE' to sign or '-l FILE' to launch the file!");
	}

	//
	// On sign mode, an output file has to be set.
	//
	if (arguments->sign_file != NULL && arguments->out_file == NULL) {
		print_usage(true, "out missing");
	}

	print_debug("process_args() Interactive password: %s\n", arguments->interactive_passwd ? "true" : "false");

	//
	// non option arguments are currently ignored
	//
	for (index = optind; index < argc; index++) {
		print_debug("process_args() Found non-option argument %s\n", argv[index]);
	}

	return true;
}

/***************************************************************************
 * The function is the actual main function of the program. The program has
 * a sign mode which processes the configuration file, by computing the file
 * hashes and encrypt the file. The launch mode uses the encrypted
 * configuration file to check the hashes and on success to launch the
 * target program and to hand over the password.
 **************************************************************************/

static bool deferred_main(const int argc, char * const argv[]) {
	s_arguments arguments = { NULL, NULL, NULL, true };

	//
	// parse the program arguments and save it in the arguments struct
	//
	process_args(argc, argv, &arguments);

	//
	// continue in sign mode
	//
	if (arguments.sign_file != NULL) {
		if (!sign_file(&arguments)) {
			print_error("deferred_main() Unable to sign file: %s\n", arguments.sign_file);
			return false;
		}

		//
		// continue in launch mode
		//
	} else {
		if (!launch_program(&arguments)) {
			print_error("deferred_main() Unable to launch program from: %s\n", arguments.launch_file);
			return false;
		}
	}

	return true;
}

/***************************************************************************
 * The main function forks a child process and traces the child. The child
 * process forks a third program, the child-child. The child traces the
 * child-child and hands over the password from the child to the
 * child-child.
 *
 * main (tracer) -> child (tracee /tracer) -> child-child (tracee)
 *                                            execv()
 *                  write password         -> read password
 **************************************************************************/

int main(const int argc, char * const argv[]) {
	pid_t pid;

	print_debug_str("Start!\n");

	//
	// set ulimit to avoid core dumps
	//
	if (!avoid_coredumps()) {
		print_error_str("main() Unable to avoid coredumps!\n");
		return EXIT_FAILURE;
	}

	//
	// fork the process
	//
	if ((pid = fork()) == -1) {
		print_error("main() Unable to fork a new process: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	//
	// child process starts the actual program (sign or launch)
	//
	if (pid == 0) {
		print_debug("main() Process: %s pid: %d was successfully forked\n",ID_HAND_OVER , getpid());

		//
		// be ready to be traced
		//
		if (ptrace(PTRACE_TRACEME) == -1) {
			print_error("main() Process: %s pid: %d - ptrace failed: %s\n", ID_HAND_OVER, getpid(), strerror(errno));
			return EXIT_FAILURE;
		}

		//
		// do the actual program execution
		//
		if (!deferred_main(argc, argv)) {
			print_error_str("main() Unable to start the actual program!\n");
			return EXIT_FAILURE;
		}

		print_debug("main() Process: %s pid: %d successfully processed program!\n",ID_HAND_OVER, getpid());

		//
		// parent process is used to trace the child
		//
	} else {
		print_debug("main() Process: %s pid: %d successfully forked child: %s pid: %d\n",ID_MAIN , getpid(), ID_HAND_OVER, pid);

		//
		// wait for the child to exit
		//
		if (!wait_for_child(ID_MAIN, pid, ID_HAND_OVER)) {
			print_error("main() Unable to wait for child: %d\n", pid);
			return EXIT_FAILURE;
		}

		print_debug("main() Process: %s pid: %d finished!\n",ID_MAIN , getpid());
	}

	print_debug_str("End!\n");
	return EXIT_SUCCESS;
}
