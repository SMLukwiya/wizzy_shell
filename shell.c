#include "shell.h"

const char *builtin_commands[] = {
  "cd", "echo", "jobs", "fg", "kill", "wait", "disown", "pwd", "export", "unset", "alias", "unalias", "set",
  "exec", "printf", "read", "test", "if", "then", "else", "fi", "case", "for", "while", "until", "break",
  "continue", "return", "exit", "help", "history", "type", "ulimit", "source", "."};

char *common_paths = "/bin:/usr/bin:/usr/local/bin";

void unix_error(char *msg) {
    fprintf(stderr, "%s: %s\n", msg, strerror(errno));
    exit(0);
}

char *Fgets(char *ptr, int n, FILE *stream) {
    if (fgets(ptr, n, stream) == NULL)
        unix_error("fgets error");
    return ptr;
}

pid_t Fork() {
    pid_t pid;

    if ((pid = fork()) < 0)
        unix_error("Fork error");

    return pid;
}

int parseline(char *buf, char **argv) {
    char *delim; /*First delimiter*/
    int argc;    /*Number of argv items*/
    int bg;      /* Background process?*/

    buf[strlen(buf) - 1] = ' '; /*replace trailing ' ' */
    while (*buf && *buf == ' ') /*Ignore leading space*/
        buf++;

    argc = 0;
    while ((delim = strchr(buf, ' '))) {
        *delim = '\0'; /* replace current delimiter */
        argv[argc++] = buf;
        buf = delim + 1; /*Move buf to next string*/
        while (*buf && *buf == ' ')
            buf++;
    }

    argv[argc] = NULL;
    if (argc == 0)
        return 1;

    if ((bg = (*argv[argc - 1] == '&')) != 0)
        argv[--argc] = NULL;

    return bg;
}

void eval(char *cmdline) {
    char *argv[MAXARGS];
    char buf[MAXLINE];
    char final_command[MAXARGS];
    int bg;
    pid_t pid;

    strcpy(buf, cmdline);
    bg = parseline(buf, argv);
    if (argv[0] == NULL) /* Ignore empty lines*/
        return;

    if (!builtin_command(argv)) {
        if ((pid = Fork()) == 0) {
            /* check for ./ or / (e.g, /bin/ls or ./prog) */
            if (!(strncmp(argv[0], "/", 1)) || !(strncmp(argv[0], "./", 2))) {
                if (execve(argv[0], argv, environ) < 0) {
                    printf("%s: command not found.\n", argv[0]);
                    exit(0);
                }
            }

            // should I attempt to first execute or look up
            if (scan_paths(argv[0], final_command) < 0) {
                printf("%s: command not found.\n", argv[0]);
                exit(0);
            }
            if (execve(final_command, argv, environ) < 0) {
                printf("%s: command not found.\n", argv[0]);
                exit(0);
            }
        }

        if (!bg) {
            int status;
            if (waitpid(pid, &status, 0) < 0)
                unix_error("waitfg: waiting error");
        } else {
            printf("%d %s\n", pid, cmdline);
        }
    }
    return;
}

int scan_paths(char *command, char *final_command) {
    char *paths;
    if (!(paths = getenv("PATH")))
        paths = common_paths;

    const char *delimiter = ":";
    char *token;
    token = strtok(paths, delimiter);
    DIR *directory;
    struct dirent *entry;

    while (token != NULL) {
        if ((directory = opendir(token)) == NULL) {
            fprintf(stderr, "Directory issues\n");
            return -1;
        }

        while ((entry = readdir(directory))) {
            if (!(strcmp(command, entry->d_name))) {
                sprintf(final_command, "%s/%s", token, command);
                return 0;
            }
            // fprintf(stderr, "Entry issues\n");
            // return -1;
        }
        // printf("Token: %s\n", entry);

        token = strtok(NULL, delimiter);
    }
    return -1;
}

int builtin_command(char **argv) {
    if (!strcmp(argv[0], "quit")) /*Quit command*/
        exit(0);

    if (!strcmp(argv[0], "&")) /*Ignore singleton &*/
        return 1;

    return 0;
}

int getShellPrompt(char *buf) {
    char hostname[MAXARGS];
    char cwd[MAXARGS];
    struct passwd *user;
    user = getpwuid(geteuid());

    if (gethostname(hostname, MAXARGS) < 0) {
        printf("%s\n", "Error");
    }

    if (!getcwd(cwd, MAXARGS))
        printf("Error\n");

    int home_dir_length = strlen(user->pw_dir);
    if (!strncmp(user->pw_dir, cwd, home_dir_length))
        strcpy(cwd, &cwd[home_dir_length]);

    sprintf(buf, "\x1b[1;34m%s@%s\x1b[0;37m:\x1b[1;32m~%s", user->pw_name, hostname, cwd);
    return 0;
}

int main() {
    char cmdline[MAXLINE];
    char buf[MAXARGS * 3];

    getShellPrompt(buf);
    while (1) {
        /* Read */
        printf("%s$ ", buf);
        Fgets(cmdline, MAXLINE, stdin);
        if (feof(stdin))
            exit(0);

        eval(cmdline);
    }
}
