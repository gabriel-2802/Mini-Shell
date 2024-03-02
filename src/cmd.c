// SPDX-License-Identifier: BSD-3-Clause

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1

/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	// if we use cd without arguments, we go to the home directory
	char *path = !dir ? getenv("HOME") : get_word(dir);

	int ret = chdir(path);

	if (dir)
		free(path);

	return !ret ? true : false;
}

static bool shell_pwd(void)
{
	char *path = getcwd(NULL, 0);

	if (!path)
		return false;

	printf("%s\n", path);
	free(path);
	return true;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	return SHELL_EXIT;
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	/* Sanity checks. */
	if (!s)
		return EXIT_FAILURE;

	char *verb = get_word(s->verb);

	/* If builtin command, execute the command. */
	if (!strcmp(verb, "cd")) {
		// we check if we have to redirect the outp
		int fd;

		if (s->out) {
			char *out_file = get_word(s->out);

			if (s->io_flags & IO_OUT_APPEND)
				fd = open(out_file, O_WRONLY | O_CREAT | O_APPEND, 0644);
			else
				fd = open(out_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);

			DIE(fd < 0, "Error opening file");
			close(fd);
			free(out_file);
		}

		if (s->in) {
			char *in_file = get_word(s->in);

			fd = open(in_file, O_RDONLY);

			DIE(fd < 0, "Error opening file");
			close(fd);
			free(in_file);
		}

		if (s->err) {
			char *err_fie = get_word(s->err);

			if (s->io_flags & IO_ERR_APPEND)
				fd = open(err_fie, O_WRONLY | O_CREAT | O_APPEND, 0644);
			else
				fd = open(err_fie, O_WRONLY | O_CREAT | O_TRUNC, 0644);

			DIE(fd < 0, "Error opening file");
			close(fd);
			free(err_fie);
		}

		free(verb);
		return shell_cd(s->params) ? EXIT_SUCCESS : EXIT_FAILURE;
	}

	if (!strcmp(verb, "pwd")) {
		int original_stdout = -1, original_stderr = -1;

		bool same_file = false;

		if (s->out && s->err) {
			char *out_file = get_word(s->out);

			char *err_file = get_word(s->err);

			// &> case
			int fd;

			if (!strcmp(out_file, err_file)) {
				same_file = true;

				if (s->io_flags & (IO_ERR_APPEND | IO_OUT_APPEND))
					fd = open(out_file, O_WRONLY | O_CREAT | O_APPEND, 0644);
				else
					fd = open(out_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);

				DIE(fd < 0, "Error opening file");
				original_stderr = dup(STDERR_FILENO);
				original_stdout = dup(STDOUT_FILENO);

				dup2(fd, STDERR_FILENO);
				dup2(fd, STDOUT_FILENO);

				close(fd);
			}

			free(out_file);
			free(err_file);
		}

		if (s->err && !same_file) {
			char *err_fie = get_word(s->err);

			int fd;

			if (s->io_flags & IO_ERR_APPEND)
				fd = open(err_fie, O_WRONLY | O_CREAT | O_APPEND, 0644);
			else
				fd = open(err_fie, O_WRONLY | O_CREAT | O_TRUNC, 0644);

			DIE(fd < 0, "Error opening file");

			// we save the original stderr file descriptor
			original_stderr = dup(STDERR_FILENO);
			dup2(fd, STDERR_FILENO);

			close(fd);
			free(err_fie);
		}

		if (s->out && !same_file) {
			char *out_fie = get_word(s->out);

			int fd;

			if (s->io_flags & IO_OUT_APPEND)
				fd = open(out_fie, O_WRONLY | O_CREAT | O_APPEND, 0644);
			else
				fd = open(out_fie, O_WRONLY | O_CREAT | O_TRUNC, 0644);

			DIE(fd < 0, "Error opening file");

			// we save the original stdout file descriptor
			original_stdout = dup(STDOUT_FILENO);
			dup2(fd, STDOUT_FILENO);

			close(fd);
			free(out_fie);
		}

		free(verb);
		bool res = shell_pwd();

		if (original_stdout != -1) {
			// we restore the original stdout file descriptor
			dup2(original_stdout, STDOUT_FILENO);
			close(original_stdout);
		}

		if (original_stderr != -1) {
			// we restore the original stderr file descriptor
			dup2(original_stderr, STDERR_FILENO);
			close(original_stderr);
		}

		return res ? EXIT_SUCCESS : EXIT_FAILURE;
	}

	if (!strcmp(verb, "exit") || !strcmp(verb, "quit")) {
		free(verb);
		return shell_exit();
	}

	/* If variable assignment, execute the assignment and return
	 * the exit status.
	 */

	if (strchr(verb, '=')) {
		char *verb_copy = strdup(verb);

		char *save_ptr;

		char *var = strtok_r(verb_copy, "=", &save_ptr);

		char *value = strtok_r(NULL, "=", &save_ptr);

		free(verb_copy);
		free(verb);
		return setenv(var, value, 1);
	}

	/* f external command:
	 *   1. Fork new process
	 *     2c. Perform redirections in child
	 *     3c. Load executable in child
	 *   2. Wait for child
	 *   3. Return exit status
	 */

	pid_t pid = fork();

	DIE(pid < 0, "Error forking");

	if (!pid) {
		// child process
		int size;

		char **argv = get_argv(s, &size);

		if (s->in) {
			char *in_file = get_word(s->in);

			int fd = open(in_file, O_RDONLY);

			DIE(fd < 0, "Error opening file");
			dup2(fd, STDIN_FILENO);

			close(fd);
			free(in_file);
		}

		bool same_file = false;

		if (s->err && s->out) {
			char *out_file = get_word(s->out);

			char *err_file = get_word(s->err);

			// &> case
			if (!strcmp(out_file, err_file)) {
				int fd;

				same_file = true;

				if (s->io_flags & (IO_ERR_APPEND | IO_OUT_APPEND))
					fd = open(err_file, O_WRONLY | O_CREAT | O_APPEND, 0644);
				else
					fd = open(err_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);

				DIE(fd < 0, "Error opening file");
				dup2(fd, STDERR_FILENO);
				dup2(fd, STDOUT_FILENO);

				close(fd);
			}

			free(out_file);
			free(err_file);
		}

		if (s->err && !same_file) {
			char *err_fie = get_word(s->err);

			int fd;

			if (s->io_flags & IO_ERR_APPEND)
				fd = open(err_fie, O_WRONLY | O_CREAT | O_APPEND, 0644);
			else
				fd = open(err_fie, O_WRONLY | O_CREAT | O_TRUNC, 0644);

			DIE(fd < 0, "Error opening file");
			dup2(fd, STDERR_FILENO);

			close(fd);
			free(err_fie);
		}

		if (s->out && !same_file) {
			char *out_fie = get_word(s->out);

			int fd;

			if (s->io_flags & IO_OUT_APPEND)
				fd = open(out_fie, O_WRONLY | O_CREAT | O_APPEND, 0644);
			else
				fd = open(out_fie, O_WRONLY | O_CREAT | O_TRUNC, 0644);

			DIE(fd < 0, "Error opening file");
			dup2(fd, STDOUT_FILENO);

			close(fd);
			free(out_fie);
		}

		int res = execvp(verb, argv);

		if (res < 0) {
			fprintf(stderr, "Execution failed for '%s'\n", verb);
			free(verb);
			exit(EXIT_FAILURE);
		}

		free(verb);
		for (int i = 0; i < size; i++)
			free(argv[i]);

		// the child process should exit once it finishes
		exit(EXIT_SUCCESS);

	} else {
		// parent process
		int child_result;

		int res = waitpid(pid, &child_result, 0);

		DIE(res < 0, "Error waiting for child");
		free(verb);

		// we return the exit status of the child process if it exited normally
		return WIFEXITED(child_result) ? WEXITSTATUS(child_result) : -1;
	}

	// we should never get here, but just in case
	free(verb);
	return 0;
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/* Execute cmd1 and cmd2 simultaneously. */
	pid_t pid = fork();

	DIE(pid < 0, "Error forking");

	if (!pid) {
		// child process
		int res = parse_command(cmd2, level + 1, father);

		// if the child commands fails, we exit with failure
		exit(!res ? EXIT_SUCCESS : EXIT_FAILURE);
	} else {
		//parent process
		int child_result;

		parse_command(cmd1, level + 1, father);
		int res = waitpid(pid, &child_result, 0);

		DIE(res < 0, "Error waiting for child");

		// we return the child return value if the child process exited normally
		return WIFEXITED(child_result) ? WEXITSTATUS(child_result) : false;
	}
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	int pipe_fd[2];

	int res = pipe(pipe_fd);

	DIE(res < 0, "Error creating pipe");

	pid_t pid = fork();

	DIE(pid < 0, "Error forking");

	if (!pid) {
		// child process
		// we close the read end of the pipe because we don't need it
		close(pipe_fd[READ]);
		// we redirect the output of the first command to the write end of the pipe
		dup2(pipe_fd[WRITE], STDOUT_FILENO);

		int res = parse_command(cmd1, level + 1, father);

		close(pipe_fd[WRITE]);

		// if the child commands fails, we exit with failure
		exit(!res ? EXIT_SUCCESS : EXIT_FAILURE);
	} else {
		// in the parent process we create another child process to execute the second command of the pipe
		pid_t second_pid = fork();

		DIE(second_pid < 0, "Error forking");

		if (!second_pid) {
			// child process
			close(pipe_fd[WRITE]);
			dup2(pipe_fd[READ], STDIN_FILENO);
			int res = parse_command(cmd2, level + 1, father);

			close(pipe_fd[READ]);
			exit(!res ? EXIT_SUCCESS : EXIT_FAILURE);
		} else {
			// we are back in the parent process
			close(pipe_fd[READ]);
			close(pipe_fd[WRITE]);
			int child_result;

			int res = waitpid(second_pid, &child_result, 0);

			DIE(res < 0, "Error waiting for child");

			// we check if the child process exited normally and if so, we return its exit status
			return WIFEXITED(child_result) ? WEXITSTATUS(child_result) : false;
		}
	}
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	/* sanity checks */

	if (c->op == OP_NONE)
		/* Execute a simple command. */
		return parse_simple(c->scmd, level + 1, c);

	switch (c->op) {
	case OP_SEQUENTIAL:
		/* Execute the commands one after the other. */
		parse_command(c->cmd1, level + 1, c);
		return parse_command(c->cmd2, level + 1, c);

	case OP_PARALLEL:
		/* Execute the commands simultaneously. */
		return (int)run_in_parallel(c->cmd1, c->cmd2, level + 1, c);

	case OP_CONDITIONAL_NZERO:
		/* Execute the second command only if the first one
		 * returns non zero.
		 */
		if (parse_command(c->cmd1, level + 1, c) != 0)
			return parse_command(c->cmd2, level + 1, c);
		return 0;

	case OP_CONDITIONAL_ZERO:
		/* Execute the second command only if the first one
		 * returns zero.
		 */

		if (!parse_command(c->cmd1, level + 1, c))
			return parse_command(c->cmd2, level + 1, c);
		return -1;

	case OP_PIPE:
		/* Redirect the output of the first command to the
		 * input of the second.
		 */
		return run_on_pipe(c->cmd1, c->cmd2, level + 1, c);

	default:
		return SHELL_EXIT;
	}
}
