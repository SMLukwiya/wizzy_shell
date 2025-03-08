#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
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
#define INITIAL_CAPACITY 64
#define MIN(x, y) (x > y ? y : x)

extern char **environ;

typedef struct {
    char *line;
    unsigned int entry_num;
} hist_entry;

typedef struct {
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

typedef struct {
    char *command_name;
    builtin_func function;
} builtin_command;

enum token_type {
    TOKEN_COMMAND,
    TOKEN_ARGUMENT,
    TOKEN_PIPE,
    TOKEN_REDIRECT_OUTPUT,
    TOKEN_REDIRECT_INPUT,
    TOKEN_REDIRECT_APPEND,
    TOKEN_REDIRECT_ERROR,
    TOKEN_REDIRECT_ERROR_APPEND,
    TOKEN_BACKGROUND,
    TOKEN_SEMICOLON,
    TOKEN_AND,
    TOKEN_OR,
    TOKEN_VARIABLE,
    TOKEN_STRING,
    TOKEN_WHITESPACE,
    TOKEN_ERROR,
    TOKEN_EOF
};

typedef struct {
    enum token_type type;
    char *value;
} token;

typedef struct {
    token **tokens;
    int token_count;
    int capacity;
    int position; // for parsing tokens later
} token_list;

typedef enum {
    NODE_COMMAND,
    NODE_PIPE,
    NODE_AND,
    NODE_OR,
    NODE_REDIRECT_OUT,
    NODE_REDIRECT_APPEND,
    NODE_REDIRECT_IN,
    NODE_REDIRECT_ERR
} AST_node_type;

typedef struct AST_node {
    AST_node_type type;
    char **command;
    char *filename;
    struct AST_node *left;
    struct AST_node *right;
    int background;
} AST_node;

int entry_number;
char *command_buf;
// remove after finishing
token_list *list = NULL;

/* APIS */
void execute_command(shell_context *ctx, char **argv, int background, int builtin_idx);
int parse_command(char *command, char **argv);
int is_builtin_command(char *command);
void free_tokens(token_list *list);

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

/* Initialize circular buffer */
void init_hist_buffer(hist_buffer *history) {
    if (!(history->entries = (hist_entry *)malloc(sizeof(hist_entry) * HISTSIZE)))
        unix_error("malloc");

    history->head_index = 0;
    history->tail_index = 0;
    history->entry_count = 0;
}

/* Add command to history buffer */
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

/* Get history entry from buffer */
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

/* Print history */
void print_history(hist_buffer *history) {
    printf("Command History:\n");
    for (int i = 0; i < history->entry_count; i++) {
        hist_entry *entry = get_entry(history, i);
        printf("%d: %s\n", entry->entry_num, entry->line);
    }
}

/* ==== Built in commands ===== */
/* History command */
int history_command(shell_context *ctx, char **args) {
    print_history(ctx->history);
    return 1;
}

/* Exit command */
int exit_command(shell_context *ctx, char **args) {
    for (int i = 0; i < ctx->history->entry_count; i++)
        free(ctx->history->entries[i].line);

    free(ctx->history->entries);
    if (list) {
        free_tokens(list);
    }
    exit(0);
}

/* Simple lookup table */
builtin_command builtins[] = {
  {"history", history_command},
  {"exit", exit_command},
  {NULL, NULL}};

/* Is command builtin */
int is_builtin_command(char *command) {
    for (int i = 0; builtins[i].command_name != NULL; i++)
        if (strcmp(command, builtins[i].command_name) == 0)
            return i;

    return -1;
}

/* Print colored shell prompt */
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

/* Remove leading and traling whitespaces from user input */
void trim_whitespace(char **start) {
    char *end;
    while (isspace((unsigned char)**start))
        (*start)++;

    end = *start + strlen(*start) - 1;
    while (end > *start && isspace((unsigned char)*end))
        end--;
    *(end + 1) = '\0';
}

/* Expand user Input from history buffer */
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

            /* Anticipate size and adjust when exceeded */
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
            /* Anticipate size and adjust when exceeded */
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

/* Tokenization */
/* add to token list */
int add_token(token_list *list, enum token_type token_type, const char *token_value) {
    /* Make room to null terminate */
    if (list->token_count >= list->capacity - 1) {
        list->capacity *= 2;
        list->tokens = realloc(list->tokens, list->capacity * sizeof(token *));
        if (!list->tokens) {
            perror("realloc");
            return -1;
        }
    }

    token *new_token_entry = malloc(sizeof(token));
    if (!new_token_entry) {
        perror("malloc");
        return -1;
    }

    char *value = strdup(token_value);
    if (!value) {
        free(new_token_entry);
        perror("malloc");
        return -1;
    }

    new_token_entry->value = value;
    new_token_entry->type = token_type;
    list->tokens[list->token_count++] = new_token_entry;
    return 0;
}

/* free token */
void free_tokens(token_list *list) {
    for (int i = 0; i < list->token_count; i++) {
        free(list->tokens[i]->value);
        free(list->tokens[i]);
    }
    free(list->tokens);
    printf("Did free list\n");
}

/* init token list */
token_list *init_token_list() {
    token_list *token_list_p;
    token **tokens_ptr_array;

    if ((token_list_p = malloc(sizeof(token_list))) == NULL) {
        perror("malloc");
        return NULL;
    }

    if ((tokens_ptr_array = (token **)malloc(INITIAL_CAPACITY * sizeof(token *))) == NULL) {
        perror("malloc");
        free(token_list_p);
        return NULL;
    }

    token_list_p->token_count = 0;
    token_list_p->tokens = tokens_ptr_array;
    token_list_p->capacity = INITIAL_CAPACITY;
    token_list_p->position = 0;
    return token_list_p;
}

/* Extract string */
char *extract_quoted_string(char **input) {
    char quote = **input;
    char *start = ++(*input);
    char *result_string = malloc(1);
    if (!result_string)
        return NULL;

    *result_string = '\0'; // empty string
    int result_string_len = 0;

    while (**input && **input != quote) {
        /* env variables within string */
        if (quote == '"' && **input == '$') {
            (*input)++;
            char variable_name[256] = {0};
            int variable_length = 0;

            while (isalnum(**input) || **input == '_')
                variable_name[variable_length++] = *(*input)++;

            variable_name[variable_length] = '\0';
            char *variable_value = getenv(variable_name);

            if (variable_value) {
                size_t actual_len = strlen(variable_value);
                char *new_result_string = realloc(result_string, result_string_len + actual_len + 1);
                if (!new_result_string) {
                    free(result_string);
                    return NULL;
                }
                result_string = new_result_string;
                strcpy(result_string + result_string_len, variable_value);
                result_string_len += actual_len;
            }
        } else {
            /* Normal string */
            char *new_result_string = realloc(result_string, result_string_len + 2);
            if (!new_result_string) {
                free(result_string);
                return NULL;
            }
            result_string = new_result_string;
            result_string[result_string_len++] = *(*input)++;
            result_string[result_string_len] = '\0';
        }
    }

    if (**input == quote)
        (*input)++;

    return result_string;
}

/* Extract tokens */
token_list *tokenize(char *command) {
    int in_quotes = 0;
    char quote_char = '\0';
    char *p = command;
    char *start;
    token_list *token_list_p = init_token_list();
    token *tokens_ptr_array;
    int expect_command = 1; // usually starts with a command

    if ((token_list_p) == NULL)
        return NULL;

    while (*p) {
        if (isspace(*p) && !in_quotes) {
            p++;
        } else if (*p == '"' || *p == '\'') {
            char *string = extract_quoted_string(&p);
            if (!string) {
                free_tokens(token_list_p);
                return NULL;
            }

            if (add_token(token_list_p, TOKEN_STRING, string) < 0) {
                free_tokens(token_list_p);
                free(string);
                return NULL;
            }

            free(string);

        } else if (*p == '|' || *p == '>' || *p == '<' || *p == '&' || *p == ';' || *p == '2') {
            int added;
            if (*p == '|') {
                p++;
                if (*p && *p == '|') {
                    added = add_token(token_list_p, TOKEN_OR, "||");
                    p++;
                } else {
                    added = add_token(token_list_p, TOKEN_PIPE, "|");
                }
                expect_command = 1;

            } else if (*p == '2' && *(p + 1) == '>') {
                p += 2;
                if (*p && *p == '>') {
                    added = add_token(token_list_p, TOKEN_REDIRECT_ERROR_APPEND, "2>>");
                    p++;
                } else {
                    added = add_token(token_list_p, TOKEN_REDIRECT_ERROR, "2>");
                }
            } else if (*p == '>') {
                p++;
                if (*p && *p == '>') {
                    added = add_token(token_list_p, TOKEN_REDIRECT_APPEND, ">>");
                    p++;
                } else {
                    added = add_token(token_list_p, TOKEN_REDIRECT_OUTPUT, ">");
                }
            } else if (*p == '<') {
                added = add_token(token_list_p, TOKEN_REDIRECT_INPUT, "<");
                p++;
            } else if (*p == '&') {
                p++;
                if (*p && *p == '&') {
                    added = add_token(token_list_p, TOKEN_AND, "&&");
                    p++;
                } else {
                    added = add_token(token_list_p, TOKEN_BACKGROUND, "&");
                }
                expect_command = 1;

            } else if (*p == ';') {
                added = add_token(token_list_p, TOKEN_SEMICOLON, ";");
                expect_command = 1;
                p++;
            }

            if (added < 0) {
                free_tokens(token_list_p);
                return NULL;
            }

        } else {
            int added;
            start = p;
            while (*p && !isspace(*p) && *p != '|' && *p != '&' && *p != ';' && *p != '>' && *p != '<' && *p != '"' && *p != '\'')
                p++;

            size_t len = p - start;
            char *str = strndup(start, len);

            if (expect_command) {
                added = add_token(token_list_p, TOKEN_COMMAND, str);
                expect_command = 0;
            } else {
                added = add_token(token_list_p, TOKEN_ARGUMENT, str);
            }
            free(str);

            if (added < 0) {
                free_tokens(token_list_p);
                return NULL;
            }
        }
    }

    token_list_p->tokens[token_list_p->token_count] = NULL;
    return token_list_p;
}

/* Test */
void print_tokens(token_list *token_list) {
    for (int i = 0; i < token_list->token_count; i++) {
        printf("Token: %-10s Type: %d\n", token_list->tokens[i]->value, token_list->tokens[i]->type);
    }
}

/* ======= PARSER ======= */
AST_node *create_command_node(char **command) {
    AST_node *node = malloc(sizeof(AST_node));
    if (!node) {
        perror("malloc");
        return NULL;
    }
    node->command = command;
    node->filename = NULL;
    node->type = NODE_COMMAND;
    node->left = NULL;
    node->right = NULL;
    node->background = 0;

    return node;
}

AST_node *create_operator_node(AST_node_type type, AST_node *left, AST_node *right) {
    AST_node *node = malloc(sizeof(AST_node));
    if (!node) {
        perror("malloc");
        return NULL;
    }
    node->command = NULL;
    node->filename = NULL;
    node->type = type;
    node->left = left;
    node->right = right;

    return node;
}

AST_node *create_redirect_node(AST_node_type type, char *filename, AST_node *left) {
    AST_node *node = malloc(sizeof(AST_node));
    if (!node) {
        perror("malloc");
        return NULL;
    }
    node->command = NULL;
    node->filename = filename;
    node->type = type;
    node->left = left;
    node->right = NULL;

    return node;
}

void free_ast_node(AST_node *node) {
    if (!node)
        return;
    free_ast_node(node->left);
    free_ast_node(node->right);
    if (node->command) {
        for (int i = 0; node->command[i]; i++)
            free(node->command[i]);
        free(node->command);
    }
    if (node->filename)
        free(node->filename);
}

token *peek(token_list *list) {
    if (list->position < list->token_count)
        return list->tokens[list->position];
    return NULL;
}

/* consume until NULL since token list is null terminated */
void consume(token_list *list) {
    if (list->position < list->token_count)
        list->position++;
}

/* Parse command, assumes entire list could be command and it's args */
AST_node *parse_command_1(token_list *list) {
    token *tok = peek(list);
    if (!tok || tok->type != TOKEN_COMMAND)
        return NULL;

    char **args = malloc(sizeof(char *) * (list->token_count + 1));
    int arg_count = 0;

    while (tok && (tok->type == TOKEN_COMMAND || tok->type == TOKEN_ARGUMENT)) {
        args[arg_count++] = strdup(tok->value);
        consume(list);
        tok = peek(list);
    }
    args[arg_count] = NULL;
    return create_command_node(args);
}

AST_node *parse_redirection(token_list *list) {
    /* construct left side ready for the redirection */
    AST_node *command = parse_command_1(list);
    token *tok = peek(list);

    while (tok && (tok->type == TOKEN_REDIRECT_OUTPUT || tok->type == TOKEN_REDIRECT_INPUT || tok->type == TOKEN_REDIRECT_ERROR || tok->type == TOKEN_REDIRECT_APPEND || tok->type == TOKEN_REDIRECT_ERROR_APPEND)) {
        /* move past redirection | */
        consume(list);
        token *filename_token = peek(list);
        if (!filename_token) {
            native_error("syntax error: filename expected for redirection");
            return NULL;
        }
        char *filename = strdup(filename_token->value);

        // create look up table for node types
        AST_node_type node_type;
        if (tok->type == TOKEN_REDIRECT_OUTPUT)
            node_type = NODE_REDIRECT_OUT;
        else if (tok->type == TOKEN_REDIRECT_INPUT)
            node_type = NODE_REDIRECT_IN;
        else if (tok->type == TOKEN_REDIRECT_ERROR)
            node_type = NODE_REDIRECT_ERR;
        else if (tok->type == TOKEN_REDIRECT_APPEND)
            node_type = NODE_REDIRECT_APPEND;

        command = create_redirect_node(node_type, filename, command);
        consume(list);
        tok = peek(list);
    }

    return command;
}

AST_node *parse_pipeline(token_list *list) {
    AST_node *l_command = parse_redirection(list);
    token *tok = peek(list);

    while (tok && tok->type == TOKEN_PIPE) {
        consume(list);
        AST_node *r_command = parse_redirection(list);
        l_command = create_operator_node(NODE_PIPE, l_command, r_command);
        tok = peek(list);
    }

    return l_command;
}

AST_node *parse_background(token_list *list) {
    AST_node *l_command = parse_pipeline(list);
    token *tok = peek(list);

    while (tok && tok->type == TOKEN_BACKGROUND) {
        consume(list);
        /* Check for common syntax errors */
        tok = peek(list);
        if (tok && (tok->type == TOKEN_PIPE || tok->type == TOKEN_OR || tok->type == TOKEN_AND)) {
            fprintf(stderr, "syntax error near unexpected token %s\n", tok->value);
            return NULL;
        }
        l_command->background = 1;
        // AST_node *r_command = parse_pipeline(list);
    }

    return l_command;
}

AST_node *parse_logical(token_list *list) {
    AST_node *l_command = parse_background(list);
    token *tok = peek(list);

    while (tok && (tok->type == TOKEN_AND || tok->type == TOKEN_OR)) {
        AST_node_type node_type = tok->type == TOKEN_AND ? NODE_AND : NODE_OR;
        consume(list);
        AST_node *r_command = parse_background(list);
        l_command = create_operator_node(node_type, l_command, r_command);
        tok = peek(list);
    }

    return l_command;
}

/* Entry */
AST_node *parse(token_list *list) {
    return parse_logical(list);
}

/* =========== Execution =========== */
void execute_command_(AST_node *node) {
    int status;
    if (!node || node->type != NODE_COMMAND)
        return;

    pid_t pid;

    if ((pid = fork()) < 0)
        return;

    if (pid == 0) {
        if (execvp(node->command[0], node->command) < 0)
            unix_error("execvp");
    } else {
        if (!node->background) {
            waitpid(pid, &status, 0);
        } else {
            printf("%d\n", pid);
        }
    }

    return;
}

void execute_redirect_out(AST_node *node) {
    if (!node || node->type != NODE_REDIRECT_OUT)
        ;

    int fd;
    if ((fd = open(node->filename, O_WRONLY | O_CREAT, 0644)) < 0)
        return;

    dup2(fd, STDOUT_FILENO);
    close(fd);
    execute_command_(node->left);
}

void execute_pipe(AST_node *node) {
    if (!node || node->type != NODE_PIPE)
        return;

    int pipefds[2];
    pid_t pid;

    if (pipe(pipefds) < 0)
        return;

    if ((pid = fork()) < 0) {
        close(pipefds[0]);
        close(pipefds[1]);
        return;
    }

    if (pid == 0) {
        close(pipefds[0]);
        dup2(pipefds[1], STDOUT_FILENO);
        close(pipefds[1]);
        execute_command_(node->left);
        exit(0);
    }

    if ((pid = fork()) < 0) {
        close(pipefds[0]);
        close(pipefds[1]);
        return;
    }

    if (pid == 0) {
        close(pipefds[1]);
        dup2(pipefds[0], STDIN_FILENO);
        close(pipefds[0]);
        execute_command_(node->right);
        exit(0);
    }

    close(pipefds[0]);
    close(pipefds[1]);
    wait(NULL);
    wait(NULL);
    return;
}

void execute(AST_node *node) {
    if (!node)
        return;

    switch (node->type) {
    case NODE_COMMAND:
        execute_command_(node);
        break;
    case NODE_REDIRECT_OUT:
        execute_redirect_out(node);
        break;
    case NODE_PIPE:
        execute_command_(node);
        break;
    default:
        fprintf(stderr, "Unknown node type\n");
    }
}

void print_ast_tree(AST_node *node) {
    if (node == NULL) {
        return;
    }

    switch (node->type) {
    case NODE_COMMAND:
        printf("Ast Command: ");
        for (int i = 0; node->command[i] != NULL; i++) {
            printf("%s ", node->command[i]);
        }
        printf("Background: %d", node->background);
        printf("\n");
        break;
    case NODE_PIPE:
        printf("Pipe:\n");
        print_ast_tree(node->left);
        print_ast_tree(node->right);
        break;
    case NODE_REDIRECT_OUT:
        printf("Redirect Out: %s\n", node->filename);
        print_ast_tree(node->left);
        break;

    case NODE_OR:
        printf("Logical or\n");
        print_ast_tree(node->left);
        print_ast_tree(node->right);
        break;

    case NODE_AND:
        printf("Logical AND\n");
        print_ast_tree(node->left);
        print_ast_tree(node->right);
        break;
    default:
        fprintf(stderr, "Not a damn thing here!\n");
    }
}
/* Parse user input */
int parse_command(char *command, char **argv) {
    char *token;
    char *delimiter = " \t";
    int argc, background;

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

/* Execute parsed command */
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

/*Evaluate command */
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

    list = tokenize(expanded_command);
    if (!list) {
        printf("Could not init");
    }
    print_tokens(list);

    AST_node *node = parse(list);
    print_ast_tree(node);
    free_ast_node(node);

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

/* Handler child termination (job mgt) */
void sig_handler(int signum) {
    while (waitpid(-1, NULL, WNOHANG) > 0)
        printf(" ");
    return;
}

/* Handle kill signal */
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

/*
<<
<<<
2>&1
*/