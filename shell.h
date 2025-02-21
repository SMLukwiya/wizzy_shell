
#ifndef _SHELL
#define _SHELL

#define _POSIX_SOURCE
#include <dirent.h>
#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAXLINE 8192 /* Max text line length */
#define MAXBUF 8192  /* Max I/O buffer size */
#define MAXARGS 128

extern char **environ;

typedef struct job {
    int job_id;
    pid_t pgid;
    int is_running;
    int is_foreground;
    int num_of_processes;
    char *command;
    struct job *next;
    struct process *process_list;
} job;

typedef struct process {
    pid_t pid;
    int status;
    int exit_code;
    struct process *next;
} process;

void eval(char *cmdline);
int parseline(char *buf, char **argv);
int builtin_command(char **argv);
int find_command();

#endif