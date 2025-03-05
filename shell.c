#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAXLINE 8192
#define MAXARGS 128

extern char **environ;

void unix_error(char *msg) {
    fprintf(stderr, "%s: %s\n", msg, strerror(errno));
    exit(0);
}

void shell_prompt(char *shell_p) {
    char hostname[MAXARGS];
    char cwd[MAXARGS];
    struct passwd *user;
    user = getpwuid(geteuid());

    if (gethostname(hostname, MAXARGS) < 0)
        sprintf(hostname, " ");

    if (!getcwd(cwd, MAXARGS))
        sprintf(cwd, " ");

    int home_dir_len = strlen(user->pw_dir);
    if (!strncasecmp(user->pw_dir, cwd, home_dir_len))
        strcpy(cwd, &cwd[home_dir_len]);

    sprintf(shell_p, "\x1b[1;32m%s@%s\x1b[0;37m:\x1b[1;34m~%s\x1b[0;37m", user->pw_name, hostname, cwd);
}

void trim_whitespace(char **start) {
    char *end;
    while (isspace((unsigned char)**start))
        (*start)++;

    /* empty command */
    if (**start == '\0')
        return;

    end = *start + strlen(*start) - 1;
    while (end > *start && isspace((unsigned char)*end))
        end--;
    *(end + 1) = '\0';
}

int parse_command(char *command, char **argv) {
    char *token;
    char *delimiter = " \t";
    int argc, background;

    trim_whitespace(&command);

    /* empty command */
    if (*command == '\0')
        return 1;

    token = strtok(command, delimiter);

    argc = 0;
    while (token != NULL) {
        argv[argc++] = token;
        token = strtok(NULL, delimiter);
    }

    if ((background = (*argv[argc - 1]) == '&'))
        argc--;
    argv[argc] = NULL;
    return background;
}

void eval_command(char *command) {
    char *argv[MAXARGS];
    int background;
    pid_t pid;

    background = parse_command(command, argv);

    if (argv[0] == NULL)
        return;

    if ((pid = fork()) < 0)
        unix_error("fork");

    if (pid == 0) {
        if (execvp(argv[0], argv) < 0)
            unix_error("execvp");
    } else {
        if (!background) {
            waitpid(pid, NULL, 0);
        }
        return;
    }
}

int main(int argc, char **argv) {
    int should_run = 1;
    char command[MAXLINE];
    char shell_p[MAXLINE];

    shell_prompt(shell_p);
    while (should_run) {
        printf("%s> ", shell_p);
        fgets(command, MAXLINE, stdin);
        if (feof(stdin))
            exit(0);
        eval_command(command);
    }
}