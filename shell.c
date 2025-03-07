#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAXLINE 8192
#define MAXARGS 128
#define HISTSIZE 1000
#define MIN(x, y) (x > y ? y : x)

extern char **environ;

typedef struct hist_entry {
    char *line;
    unsigned int entry_num;
} hist_entry;

typedef struct hist_buffer {
    hist_entry *entries;
    int head_index;
    int tail_index;
    int entry_count;
} hist_buffer;

typedef struct {
    hist_buffer *history;
} shell_context;

typedef int (*builtin_func)(shell_context *ctx, char **args);
typedef void signal_handler(int signum);

typedef struct builtin_command {
    char *command_name;
    builtin_func function;
} builtin_command;

int entry_number;
char *command_buf;

/* APIS */
void execute_command(shell_context *ctx, char **argv, int background, int builtin_idx);
int parse_command(char *command, char **argv);
int is_builtin_command(char *command);

void unix_error(char *msg) {
    fprintf(stderr, "%s: %s\n", msg, strerror(errno));
    exit(0);
}

void native_error(char *msg) {
    fprintf(stderr, "%s\n", msg);
    return;
}

void signal_register(int signum, signal_handler handler) {
    struct sigaction action;
    action.sa_handler = handler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;

    if (sigaction(signum, &action, NULL) < 0)
        unix_error("signal");

    return;
}

void init_hist_buffer(hist_buffer *history) {
    if (!(history->entries = (hist_entry *)malloc(sizeof(hist_entry) * HISTSIZE)))
        unix_error("malloc");

    history->head_index = 0;
    history->tail_index = 0;
    history->entry_count = 0;
}

void add_to_history(hist_buffer *history, char *command) {
    hist_entry entry;

    if (history->entry_count == HISTSIZE) {
        free(history->entries[history->tail_index].line);
        history->tail_index = (history->tail_index + 1) % HISTSIZE;
    } else
        history->entry_count++;

    entry_number++;
    entry.entry_num = entry_number;
    entry.line = strdup(command);
    history->head_index = history->entry_count == 1 ? 0 : (history->head_index + 1) % HISTSIZE;
    history->entries[history->head_index] = entry;
}

hist_entry *get_entry(hist_buffer *history, int index) {
    if (index < 0) {
        /* offset */
        index = history->entry_count + index;
    }

    if (index < 0 || index >= history->entry_count)
        return NULL;
    int idx = (history->tail_index + index) % HISTSIZE;

    return &(history->entries[idx]);
}

void print_history(hist_buffer *history) {
    printf("Command History:\n");
    for (int i = 0; i < history->entry_count; i++) {
        hist_entry *entry = get_entry(history, i);
        printf("%d: %s\n", entry->entry_num, entry->line);
    }
}

/* Built in commands */
int history_command(shell_context *ctx, char **args) {
    print_history(ctx->history);
    return 1;
}

int exit_command(shell_context *ctx, char **args) {
    for (int i = 0; i < ctx->history->entry_count; i++)
        free(ctx->history->entries[i].line);

    free(ctx->history->entries);
    exit(0);
}

builtin_command builtins[] = {
  {"history", history_command},
  {"exit", exit_command},
  {NULL, NULL}};

int is_builtin_command(char *command) {
    for (int i = 0; builtins[i].command_name != NULL; i++)
        if (strcmp(command, builtins[i].command_name) == 0)
            return i;

    return -1;
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

    end = *start + strlen(*start) - 1;
    while (end > *start && isspace((unsigned char)*end))
        end--;
    *(end + 1) = '\0';
}

char *expand_history(shell_context *ctx, char *command) {
    char *p = command;
    size_t expanded_length = strlen(command) * 2; // anticipate
    char *expanded_command = (char *)malloc(expanded_length);
    char *current_pos = expanded_command;
    *current_pos = '\0'; // empty string
    char *end_pos = expanded_command + expanded_length - 1;

    if (!expanded_command) {
        perror("malloc");
        return NULL;
    }

    while (*p) {
        if (*p == '!') {
            p++;
            hist_entry *history_entry = NULL;

            if (*p == '!') { // !
                p++;
                history_entry = get_entry(ctx->history, ctx->history->head_index);
            } else if (isdigit(*p)) {
                int index = 0;
                /* extract digit */
                while (isdigit(*p)) { // !n
                    index = (index * 10) + (*p - '0');
                    p++;
                }

                history_entry = get_entry(ctx->history, index - 1); // zero based(idx-1)
            } else if (*p == '-') {                                 // !-n
                p++;
                int offset = 0;
                /* extract offset */
                while (isdigit(*p)) {
                    offset = (offset * 10) + (*p - '0');
                    p++;
                }

                history_entry = get_entry(ctx->history, -offset);
            } else { // !pattern
                const char *start = p;
                /* extract pattern */
                while (*p && !isspace(*p))
                    p++;

                size_t str_length = p - start;
                char *pattern = strndup(start, str_length);
                /* try and get recent command with pattern */
                for (int i = ctx->history->entry_count - 1; i >= 0; i--) {
                    hist_entry *entry = get_entry(ctx->history, i);
                    if (strncmp(entry->line, pattern, MIN(str_length, strlen(entry->line))) == 0) {
                        history_entry = entry;
                        break;
                    }
                }
                free(pattern);
            }

            if (!history_entry) {
                native_error("No commands in history");
                free(expanded_command);
                return NULL;
            }

            if (current_pos == end_pos) {
                size_t len = strlen(expanded_command);
                expanded_length *= 2;
                expanded_command = realloc(expanded_command, expanded_length);
                end_pos = expanded_command + expanded_length;
                current_pos = expanded_command + len;
            }
            strcat(expanded_command, history_entry->line);
            current_pos += strlen(history_entry->line);
        } else {
            if (current_pos == end_pos) {
                size_t len = strlen(expanded_command);
                expanded_length *= 2;
                expanded_command = realloc(expanded_command, expanded_length);
                end_pos = expanded_command + expanded_length;
                current_pos = expanded_command + len;
            }
            *current_pos = *p;
            current_pos++;
            *current_pos = '\0';
            p++;
        }
    }
    // realloc one last time
    size_t actual_size = strlen(expanded_command);
    expanded_command = realloc(expanded_command, actual_size);
    return expanded_command;
}

int parse_command(char *command, char **argv) {
    char *token;
    char *delimiter = " \t";
    int argc, background;

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

void execute_command(shell_context *ctx, char **argv, int background, int builtin_idx) {
    pid_t pid;
    int status;

    if (builtin_idx != -1 && !background) {
        builtins[builtin_idx].function(ctx, argv);
    } else {
        if ((pid = fork()) < 0)
            unix_error("fork");

        if (pid == 0) {
            if (builtin_idx != -1)
                builtins[builtin_idx].function(ctx, argv);
            else {
                if (execvp(argv[0], argv) < 0)
                    unix_error("execvp");
            }
        } else {
            if (!background) {
                waitpid(pid, &status, 0);
            } else {
                printf("%d\n", pid);
            }
        }
    }
    return;
}

void eval_command(char *command, shell_context *ctx) {
    char *argv[MAXARGS];
    int background;
    int status;
    int builtin_idx;
    int expanded = 0;
    char *expanded_command = command;

    trim_whitespace(&expanded_command);
    /* empty command */
    if (*expanded_command == '\0')
        return;

    if (strchr(expanded_command, '!') != NULL) {
        if ((expanded_command = expand_history(ctx, expanded_command)) != NULL) {
            expanded = 1;
        }
    }

    add_to_history(ctx->history, expanded_command);
    memset(argv, 0, sizeof(argv));
    background = parse_command(expanded_command, argv);

    if (!argv[0])
        return;

    builtin_idx = is_builtin_command(argv[0]);
    int i = 0;
    execute_command(ctx, argv, background, builtin_idx);
    if (expanded)
        free(expanded_command);
    return;
}

void sig_handler(int signum) {
    while (waitpid(-1, NULL, WNOHANG) > 0)
        printf(" ");
    return;
}

void sig_term_handler(int signum) {
    write(STDOUT_FILENO, " \n", 3);
    memset(command_buf, 0, MAXLINE);
}

int main(int argc, char **argv) {
    int should_run = 1;
    char command[MAXLINE];
    char shell_p[MAXLINE];
    hist_buffer history;
    shell_context ctx = {.history = &history};
    command_buf = command;

    init_hist_buffer(ctx.history);
    entry_number = 0;

    // signal(SIGCHLD, sig_handler);
    signal_register(SIGINT, sig_term_handler);

    shell_prompt(shell_p);
    while (should_run) {
        printf("%s> ", shell_p);
        fgets(command, MAXLINE, stdin);
        if (feof(stdin)) {
            exit(0);
        }
        eval_command(command, &ctx);
    }
}