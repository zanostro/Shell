#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <linux/limits.h>
#include <sys/wait.h>
#include <signal.h>

#define MAX_LINE_LENGTH 16384
#define MAX_TOKENS 50
#define MAX_PROMPT_LENGTH 9

char line[MAX_LINE_LENGTH];
char *tokens[MAX_TOKENS];
int token_count = 0;
char originalLine[MAX_LINE_LENGTH];
int background = 0;
char prompt[MAX_PROMPT_LENGTH] = "mysh";
char procfs_path[PATH_MAX] = "/proc";
volatile int last_exit_status = 0;
int debug_level = 0;
extern int errno ;

typedef struct {
    const char *name;
    int (*func)(int argc, char **argv);
    const char *description;
} Command;

typedef struct {
    int pid;
    int ppid;
    char state;
    char name[256];
} ProcessInfo;

int tokenize(char *line);
int cmd_help(int argc, char **argv);
int cmd_exit(int argc, char **argv);
int cmd_status(int argc, char **argv);
int cmd_prompt(int argc, char **argv);
int cmd_debug(int argc, char **argv);
int cmd_print(int argc, char **argv);
int cmd_echo(int argc, char **argv);
int cmd_len(int argc, char **argv);
int cmd_sum(int argc, char **argv);
int cmd_calc(int argc, char **argv);
int cmd_basename(int argc, char **argv);
int cmd_dirname(int argc, char **argv);
int cmd_dirch(int argc, char **argv);
int cmd_dirwd(int argc, char **argv);
int cmd_dirmk(int argc, char **argv);
int cmd_dirrm(int argc, char **argv);
int cmd_dirls(int argc, char **argv);
int cmd_rename(int argc, char **argv);
int cmd_unlink(int argc, char**argv);
int cmd_remove(int argc, char **argv);
int cmd_linkhard(int argc, char **argv);
int cmd_linksoft(int argc, char **argv);
int cmd_linkread(int argc, char **argv);
int cmd_linklist(int argc, char **argv);
int cmd_cpcat(int argc, char **argv);
int cmd_pid(int argc, char **argv);
int cmd_ppid(int argc, char **argv);
int cmd_uid(int argc, char **argv);
int cmd_euid(int argc, char **argv);
int cmd_gid(int argc, char **argv);
int cmd_egid(int argc, char **argv);
int cmd_sysinfo(int argc, char **argv);
int cmd_proc(int argc, char **argv);
int cmd_pids(int argc, char **argv);
int cmd_pinfo(int argc, char **argv);
int numeric_filter(const struct dirent *dir);
int compare_pids(const void *a, const void *b);
int cmd_waitone(int argc, char **argv);
int cmd_waitall(int argc, char **argv);
int cmd_pipes(int argc, char **argv);


Command builtins[] = {
    {"help", cmd_help, "Display help information"},
    {"exit", cmd_exit, "Exit the shell with an optional status"},
    {"status", cmd_status, "Display the status of the last executed command"},
    {"prompt", cmd_prompt, "Set or display the shell prompt"},
    {"debug", cmd_debug, "Set or display the debug level"},
    {"print", cmd_print, "Prints arguments without newline"},
    {"echo", cmd_echo, "Prints argments whith newline"},
    {"len", cmd_len, "Prints lenght of arguments"},
    {"sum", cmd_sum, "Sums arguments"},
    {"calc", cmd_calc, "Calculates two variables"},
    {"basename", cmd_basename, "Prints base name of directory"},
    {"dirname", cmd_dirname, "Prints parent directory"},
    {"dirch", cmd_dirch, "Switches curent working directory"},
    {"dirwd", cmd_dirwd, "Prints curent working directory"},
    {"dirmk", cmd_dirmk, "Creates a new directory"},
    {"dirrm", cmd_dirrm, "Removes a directory"},
    {"dirls", cmd_dirls, "Prints directory"},
    {"rename", cmd_rename, "Renames a file"},
    {"unlink", cmd_unlink, "Unlinks a file"},
    {"remove", cmd_remove, "Removes a file"},
    {"linkhard", cmd_linkhard, "Create a hard link with the given name to the target"},
    {"linksoft", cmd_linksoft, "Create a symbolic link with the given name to the target"},
    {"linkread", cmd_linkread, "Display the target of the specified symbolic link"},
    {"linklist", cmd_linklist, "List all hard links to a specified file in the current directory"},
    {"cpcat", cmd_cpcat, "Cp and cat combined"},
    {"pid", cmd_pid, "Display the PID of the shell"},
    {"ppid", cmd_ppid, "Display the PID of the shell's parent process"},
    {"uid", cmd_uid, "Display the UID of the shell's owner"},
    {"euid", cmd_euid, "Display the EUID of the shell's process"},
    {"gid", cmd_gid, "Display the GID of the shell's process"},
    {"egid", cmd_egid, "Display the EGID of the shell's process"},
    {"sysinfo", cmd_sysinfo, "Display basic system information"},
    {"proc", cmd_proc, "Set or display the path to the procfs"},
    {"pids", cmd_pids, "List all PIDs of running processes sorted numerically"},
    {"pinfo", cmd_pinfo, "Display detailed information about all running processes"},
    {"waitone", cmd_waitone, "Wait for a specific or any child process"},
    {"waitall", cmd_waitall, "Wait for all child processes"},
    {"pipes", cmd_pipes, "Execute command pipeline"},

    {NULL, NULL, NULL}  
};

int numeric_filter(const struct dirent *dir) {
    const char *pid = dir->d_name;
    while (*pid) {
        if (!isdigit(*pid)) return 0;
        pid++;
    }
    return 1;
}

int compare_pids(const void *a, const void *b) {
    int pid1 = atoi(*(const char **)a);
    int pid2 = atoi(*(const char **)b);
    return (pid1 - pid2);
}

int compare(const void *a, const void *b) {
    ProcessInfo *pa = (ProcessInfo *)a;
    ProcessInfo *pb = (ProcessInfo *)b;
    return (pa->pid - pb->pid);
}

int cmd_pipes(int argc, char **argv) {
    int num_pipes = argc - 2;
    int pipe_fds[2 * num_pipes];

    for (int i = 0; i < num_pipes; i++) {
        pipe(pipe_fds + 2 * i);
    }

    int status = 0;

    for (int i = 0; i < argc - 1; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            if (i > 0) {
                dup2(pipe_fds[2 * (i - 1)], 0);
            }
            if (i < num_pipes) {
                dup2(pipe_fds[2 * i + 1], 1);
            }
            for (int j = 0; j < 2 * num_pipes; j++) {
                close(pipe_fds[j]);
            }
            tokenize(argv[i + 1]);
            char *sub_args[MAX_TOKENS];
            for (int j = 0; j < token_count; j++) {
                sub_args[j] = tokens[j];
            }
            sub_args[token_count] = NULL;
            for (int k = 0; builtins[k].name != NULL; k++) {
                if (strcmp(builtins[k].name, sub_args[0]) == 0) {
                    _exit(builtins[k].func(token_count, sub_args));
                }
            }
            execvp(sub_args[0], sub_args);
            _exit(EXIT_FAILURE);
        }
    }
    for (int i = 0; i < 2 * num_pipes; i++) {
        close(pipe_fds[i]);
    }
    while (wait(&status) != -1 || errno != ECHILD);

    return status;
}


int cmd_waitone(int argc, char **argv) {
    pid_t pid;
    int status = 0;
    if (argc == 2) {
        pid = atoi(argv[1]);
    } else {
        pid = -1;  
    }
    if (waitpid(pid, &status, 0) == -1) {
        return last_exit_status;
    }
    return WEXITSTATUS(status);
}

int cmd_waitall(int argc, char **argv) {
    int status;
    while (waitpid(-1, &status, 0) > 0);
    fflush(stdout);
    return 0;
}



int cmd_pinfo(int argc, char **argv) {
    struct dirent **namelist;
    int n, count = 0;
    n = scandir(procfs_path, &namelist, numeric_filter, NULL);
    if (n < 0) {
        int err = errno;
        perror("pinfo");
        return err;
    }

    ProcessInfo *processes = malloc(n * sizeof(ProcessInfo));

    for (int i = 0; i < n; i++) {
        char stat_path[1024];
        sprintf(stat_path, "%s/%s/stat", procfs_path, namelist[i]->d_name);

        FILE *fp = fopen(stat_path, "r");
        if (fp) {
            ProcessInfo info;
            if (fscanf(fp, "%d (%[^)]) %c %d", &info.pid, info.name, &info.state, &info.ppid) == 4) {
                processes[count++] = info;
            }
            fclose(fp);
        }
        free(namelist[i]);
    }
    free(namelist);

    qsort(processes, count, sizeof(ProcessInfo), compare);

    printf("%5s %5s %6s %s\n", "PID", "PPID", "STANJE", "IME");
    for (int i = 0; i < count; i++) {
        printf("%5d %5d %6c %s\n", processes[i].pid, processes[i].ppid, processes[i].state, processes[i].name);
    }
    fflush(stdin);
    free(processes);
    return 0;
}

int cmd_pids(int argc, char **argv) {
    struct dirent **namelist;
    int n;
    char *proc_path = procfs_path; 

    n = scandir(proc_path, &namelist, numeric_filter, NULL);
    if (n < 0) {
        int err = errno;
        perror("pids");
        return err;
    }

    char **pids = malloc(n * sizeof(char *));

    for (int i = 0; i < n; i++) {
        pids[i] = strdup(namelist[i]->d_name);
    }

    qsort(pids, n, sizeof(char *), compare_pids);

    for (int i = 0; i < n; i++) {
        printf("%s\n", pids[i]);
        free(pids[i]);
    }
    fflush(stdin);
    free(pids);
    while (n--) free(namelist[n]);
    free(namelist);

    return 0;
}


int cmd_proc(int argc, char **argv) {

    if (argc == 1) {
        printf("%s\n", procfs_path);
    } else if (argc == 2) {
        if (access(argv[1], F_OK | R_OK) != 0) {
            return 1; 
        }
        strncpy(procfs_path, argv[1], PATH_MAX);
    }
    return 0;
}


int cmd_sysinfo(int argc, char **argv) {
    struct utsname sysinfo;
    if (uname(&sysinfo) != 0) {
        int err = errno;
        perror("uname");
        return err;
    }

    printf("Sysname: %s\n", sysinfo.sysname);
    printf("Nodename: %s\n", sysinfo.nodename);
    printf("Release: %s\n", sysinfo.release);
    printf("Version: %s\n", sysinfo.version);
    printf("Machine: %s\n", sysinfo.machine);
    fflush(stdout);

    return 0;
}


int cmd_egid(int argc, char **argv) {
    printf("%u\n", getegid());
    fflush(stdout);
    return 0;
}

int cmd_gid(int argc, char **argv) {
    printf("%u\n", getgid());
    fflush(stdout);
    return 0;
}

int cmd_euid(int argc, char **argv) {
    printf("%u\n", geteuid());
    fflush(stdout);
    return 0;
}

int cmd_uid(int argc, char **argv) {
    printf("%u\n", getuid());
    fflush(stdout);
    return 0;
}

int cmd_ppid(int argc, char **argv) {
    printf("%d\n", getppid());
    fflush(stdout);
    return 0;
}

int cmd_pid(int argc, char **argv) {
    printf("%d\n", getpid());
    fflush(stdout);
    return 0;
}

int cmd_cpcat(int argc, char **argv) {
    int fd_in, fd_out;
    char* buffer = malloc(MAX_LINE_LENGTH);
    ssize_t bytes_read, bytes_written;

    if (argc > 1 && argv[1][0] != '-') {
        fd_in = open(argv[1], O_RDONLY);
        if (fd_in == -1) {
            int err = errno;
            perror("cpcat");
            free(buffer);
            return err;  
        }
    } else {
        fd_in = STDIN_FILENO;
    }

    if (argc > 2) {
        fd_out = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd_out == -1) {
            int err = errno;
            perror("cpcat");
            close(fd_in);
            free(buffer);  
            return errno;
        }
    } else {
        fd_out = STDOUT_FILENO;
    }

    while ((bytes_read = read(fd_in, buffer, MAX_LINE_LENGTH)) > 0) {
        bytes_written = write(fd_out, buffer, bytes_read);
        if (bytes_written == -1) {
            int err = errno;
            perror("cpcat");
            close(fd_in);
            close(fd_out);
            free(buffer);
            return err;
        }
    }

    if (bytes_read == -1) {
        int err = errno;
        perror("Napaka pri branju iz vhodnega vira");
        close(fd_in);
        close(fd_out);
        free(buffer);
        return err;
    }

    if (fd_in != STDIN_FILENO) close(fd_in);
    if (fd_out != STDOUT_FILENO) close(fd_out);

    free(buffer);
    return 0;
}



int cmd_linklist(int argc, char **argv) {
    if (argc != 2) {
        return 1; 
    }

    struct stat fileStat;
    if (stat(argv[1], &fileStat) != 0) {
        int err = errno;
        perror("linklist");
        return err;
    }

    DIR *dir;
    struct dirent *entry;
    struct stat entryStat;
    char *cwd = malloc(MAX_LINE_LENGTH);
    
    getcwd(cwd, MAX_LINE_LENGTH);
    dir = opendir(cwd);
    if (dir == NULL) {
        int err = errno;
        perror("linklist");
        free(cwd);
        return err;
    }

    int first = 1;
    while ((entry = readdir(dir)) != NULL) {
        if (stat(entry->d_name, &entryStat) == 0) {
            if (entryStat.st_ino == fileStat.st_ino && entryStat.st_dev == fileStat.st_dev) {
                if (!first) {
                    printf("  ");
                }
                printf("%s", entry->d_name);
                first = 0;  
            }
        }
    }
    printf("\n");

    closedir(dir);
    free(cwd);
    fflush(stdout);
    return 0;
}




int cmd_linkread(int argc, char **argv) {
    if (argc != 2) {
        return 1;
    }

    char *buffer;
    ssize_t len;
    size_t bufsize = 1024; 

    buffer = malloc(bufsize);

    while ((len = readlink(argv[1], buffer, bufsize)) == bufsize) {
        bufsize *= 2;
        char *new_buffer = realloc(buffer, bufsize);
        buffer = new_buffer;
    }

    if (len == -1) {
        int err = errno;
        perror("linkread");
        free(buffer);
        return err;
    }

    buffer[len] = '\0';  
    printf("%s\n", buffer);
    free(buffer);
    fflush(stdout);
    return 0;
}


int cmd_linksoft(int argc, char **argv) {
    if (argc != 3) {
        return 1;
    }

    int result = symlink(argv[1], argv[2]);
    if (result != 0) {
        int err = errno;
        perror("linksoft");
        return err; 
    }

    return 0;
}


int cmd_linkhard(int argc, char **argv) {

    if (argc != 3)
        return 1;  

    if (link(argv[1], argv[2]) != 0) {
        int err = errno;
        perror("linkhard"); 
        return err; 
    }

    return 0;
}


int cmd_remove(int argc, char **argv) {
    if (argc != 2) {
        return 1; 
    }

    if (remove(argv[1]) != 0) {
        int err = errno;
        perror("remove");  
        return err; 
    }
    return 0;  
}


int cmd_unlink(int argc, char **argv) {
    if (argc != 2) {
        return 1;
    }

    if (unlink(argv[1]) != 0) {
        int err = errno;
        perror("unlink");
        return err;  
    }

    return 0;  
}


int cmd_rename(int argc, char **argv) {

    if (argc != 3) {
        return 1;
    }

    int result = rename(argv[1], argv[2]);
    if (result != 0) {
        int err = errno;
        perror("rename");  
        return err;
    }

    return 0; 
}


int cmd_dirls(int argc, char **argv){
    DIR *dir;
    struct dirent *entry;
    const char *directory = argc > 1 ? argv[1] : ".";

    dir = opendir(directory);
    if (dir == NULL) {
        int err = errno;
        perror("dirls");
        return err;
    }

    while ((entry = readdir(dir)) != NULL) {
        printf("%s  ", entry->d_name);
    }
    printf("\n");
    closedir(dir);
    fflush(stdout);
    return 0;
}


int cmd_dirrm(int argc, char **argv){

    if(argc > 1){
        if(rmdir(argv[1]) != 0){
            int err = errno;
            perror("dirrm");
            return err;
        }
        return 0;
    }
    return 1;
}

int cmd_dirmk(int argc, char **argv){

    if(argc > 1){
        if(mkdir(argv[1], 0700) != 0){
            int err = errno;
            perror("dirmk");
            return err;
        }
        return 0;
    }

    return 1;
}


int cmd_dirwd(int argc, char **argv){

    char *buff = malloc(MAX_LINE_LENGTH*sizeof(char));
    if(getcwd(buff, MAX_LINE_LENGTH*sizeof(char)) == 0){
        return 1;
    }
    if(argc > 1){
        if(strcmp(argv[1], "full") == 0){
            printf("%s\n", buff);
            return 0;
        }
        else if(strcmp(argv[1], "base") == 0){
            char *lastSlash = buff;
            int ptr = 0;

            while(buff[ptr] != 0){
                if(buff[ptr] == '/')
                    lastSlash = &buff[ptr];
                ptr++;
            }
            if(ptr > 1)
                lastSlash++;

            printf("%s\n", lastSlash);
            fflush(stdout);
            return 0;
        }
        else
            return 1;
    }
    
    char *lastSlash = buff;
    int ptr = 0;

    while(buff[ptr] != 0){
        if(buff[ptr] == '/')
                lastSlash = &buff[ptr];
        ptr++;
    }
    if(ptr > 1)
        lastSlash++;
    printf("%s\n", lastSlash);
    fflush(stdout);
    return 0;
}


int cmd_dirch(int argc, char **argv){
    int status;

    if(argc == 1){
        if(chdir("/") != 0){
            int error = errno;
            perror("dirch");
            return error;
        }
        return 0;
    }

    if(chdir(argv[1]) != 0){
        int error = errno;
        perror("dirch");
        return error;
    }
    return 0;
}

int cmd_basename(int argc, char **argv){
    if(argc < 2) return 1;
    char *lastSlash = argv[1];
    int ptr = 0;

    while(argv[1][ptr] != 0){
        if(argv[1][ptr] == '/')
            lastSlash = &argv[1][ptr];
        ptr++;
    }
    if(ptr > 1)
        lastSlash++;
    printf("%s\n", lastSlash);
    fflush(stdout);
    return 0;

}

int cmd_dirname(int argc, char **argv){
    if(argc < 2) return 1;

    char *lastSlash = argv[1];
    int ptr = 0;

    while(argv[1][ptr] != 0){
        if(argv[1][ptr] == '/')
            lastSlash = &argv[1][ptr];
        ptr++;
    }
    char temp = lastSlash[0];
    lastSlash[0] = 0;

    printf("%s\n", argv[1]);
    fflush(stdout);
    lastSlash[0] = temp; 
    return 0;
}


int cmd_calc(int argc, char **argv){

    if(argc > 3){
        int res = 0;
        char op = argv[2][0];
        int a = atoi(argv[1]);
        int b = atoi(argv[3]);

        switch (op){
            case '+':
                res = a + b;
                break;
            case '-':
                res = a - b;
                break;
            case '*':
                res = a * b;
                break;
            case '%':
                res = a % b;
                break;
            case '/':
                if(b == 0)
                    return 1;
                res = a / b;
                break;
            default :
                return 1;
        }

        printf("%d\n", res);
        fflush(stdout);

        return 0;
    }
    return 1;
}

int cmd_sum(int argc, char **argv){

    int sum = 0;

    for(int i = 1; i<argc; i++){
        sum += atoi(argv[i]);
    }
    printf("%d\n", sum);
    fflush(stdout);

    return 0;
}

int cmd_len(int argc, char **argv){

    int counter = 0;

    for(int i = 1; i < argc; i++){
        int l = 0;
        while(argv[i][l] != 0){
            l++;
            if(l == MAX_LINE_LENGTH)
                return 1;
        }
        counter += l;
    }
    printf("%d\n", counter);
    fflush(stdout);

    return 0;
}


int cmd_print(int argc, char **argv){

    if(argc > 1){
        --argc;
        for(int i = 1; i < argc; i++)
            printf("%s ", argv[i]);
        printf("%s", argv[argc]);
        fflush(stdout);
    }
    else{
        return 1;
    }
    return 0;
}

int cmd_echo(int argc, char **argv){

    if(argc == 1){
        printf("\n");
        fflush(stdout);
        return 0;
    }

    int exit = cmd_print(argc, argv);

    if(exit == 0)
        printf("\n");
        fflush(stdout);
    return exit;
}


int cmd_debug(int argc, char **argv) {
    if (argc > 1) {
        int level = atoi(argv[1]);  
        if (level < 0) {
            level = 0;  
        }
        debug_level = level;
    } else {
        printf("%d\n", debug_level);
        fflush(stdout);
    }
    
    return 0;
}


int cmd_help(int argc, char **argv) {
    for (int i = 0; builtins[i].name != NULL; i++) {
        printf("%s: %s\n", builtins[i].name, builtins[i].description);
        fflush(stdout);
    }
    return 0;
}

int cmd_exit(int argc, char **argv) {
    int status = last_exit_status; 
    if (argc > 1) {
        status = atoi(argv[1]); 
    }
    exit(status);
}

int cmd_status(int argc, char **argv) {
    printf("%d\n", last_exit_status);
    fflush(stdout);
    return last_exit_status;
}

int cmd_prompt(int argc, char **argv) {
    if (argc == 1) {
        printf("%s\n", prompt);
        fflush(stdout);
    } else {
        
        if (strlen(argv[1]) >= MAX_PROMPT_LENGTH) {
            return 1;
        } else {
            strcpy(prompt, argv[1]);
        }
    }
    return 0;
}

void execute_command(int argc, char **argv, char *input_file, char *output_file) {
    if (argc == 0) return;
    
    int is_builtin = 0;
    for (int i = 0; builtins[i].name != NULL; i++) {
        if (strcmp(builtins[i].name, argv[0]) == 0) {
            is_builtin = 1;
            break;
        }
    }

    if (is_builtin && !background) {
        int saved_stdin = dup(STDIN_FILENO);
        int saved_stdout = dup(STDOUT_FILENO);
        if (input_file) {
            int fd_in = open(input_file, O_RDONLY);
            if (fd_in == -1) {
                perror("open input_file");
                return;
            }
            dup2(fd_in, STDIN_FILENO);
            close(fd_in);
        }
        if (output_file) {
            int fd_out = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd_out == -1) {
                perror("open output_file");
                return;
            }
            dup2(fd_out, STDOUT_FILENO);
            close(fd_out);
        }

        for (int i = 0; builtins[i].name != NULL; i++) {
            if (strcmp(builtins[i].name, argv[0]) == 0) {
                last_exit_status = builtins[i].func(argc, argv);
                break;
            }
        }

        fflush(stdout);
        dup2(saved_stdin, STDIN_FILENO);
        dup2(saved_stdout, STDOUT_FILENO);
        close(saved_stdin);
        close(saved_stdout);
        return;

    } else {
        pid_t pid = fork();
        if (pid == 0) {
            if (input_file) {
                int fd_in = open(input_file, O_RDONLY);
                if (fd_in == -1) {
                    perror("open input_file");
                    exit(EXIT_FAILURE);
                }
                dup2(fd_in, STDIN_FILENO);
                close(fd_in);
            }
            if (output_file) {
                int fd_out = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (fd_out == -1) {
                    perror("open output_file");
                    exit(EXIT_FAILURE);
                }
                dup2(fd_out, STDOUT_FILENO);
                close(fd_out);
            }
            if (execvp(argv[0], argv) == -1) {
                perror("exec");
                exit(EXIT_FAILURE);
            }
        } else if (pid > 0) {
            if (!background) {
                int status;
                waitpid(pid, &status, 0);
                last_exit_status = WEXITSTATUS(status);
            }
        }
    }
}





void print_tokens() {
    if (debug_level > 0) {
        printf("Input line: '%s'\n", originalLine);
        for (int i = 0; i < token_count; i++) {
            printf("Token %d: '%s'\n", i, tokens[i]);
        }
        fflush(stdout);
    }
}

void parse_command_features(char **input_file, char **output_file) {
    background = 0;

    if (token_count > 0 && strcmp(tokens[token_count - 1], "&") == 0) {
        background = 1;
        token_count--;
    }

    if (token_count > 1 && tokens[token_count - 2][0] == '<' && tokens[token_count - 1][0] == '>') {
        *input_file = tokens[token_count - 2] + 1;
        *output_file = tokens[token_count - 1] + 1;
        token_count -= 2;
    } else if (token_count > 0 && tokens[token_count - 1][0] == '>') {
        *output_file = tokens[token_count - 1] + 1;
        token_count--;
    } else if (token_count > 0 && tokens[token_count - 1][0] == '<') {
        *input_file = tokens[token_count - 1] + 1;
        token_count--;
    }

    if (debug_level > 0) {
        if (*input_file) {
            printf("Input redirect: '%s'\n", *input_file);
            fflush(stdout);
        }
        if (*output_file) {
            printf("Output redirect: '%s'\n", *output_file);
            fflush(stdout);
        }
        if (background) {
            printf("Background: 1\n");
            fflush(stdout);
        }
    }
}



int tokenize(char *line) {
    char *cursor = line;
    token_count = 0;
    int in_quotes = 0;
    char *token_start = NULL;
    //char *tokens[MAX_TOKENS];

    for (; *cursor; cursor++) {
        if (*cursor == '"') {
            in_quotes = !in_quotes;
            if (!in_quotes) {
                *cursor = '\0';
                if (token_start && token_count < MAX_TOKENS) {
                    tokens[token_count++] = token_start;
                    token_start = NULL;
                }
            } else {
                token_start = cursor + 1;
            }
        } 
        else if (!in_quotes && *cursor == '#') {    
           
            if (cursor == line || *(cursor - 1) == ' ' || *(cursor - 1) == 0) {
                if (token_start && token_count < MAX_TOKENS) {
                    *cursor = '\0';
                    tokens[token_count++] = token_start;
                    token_start = NULL;
                }
                break;
            }
        }
        else if (!in_quotes && isspace((unsigned char)*cursor)) {
            if (!token_start) {
                continue;
            }
            *cursor = '\0';
            if (token_start && token_count < MAX_TOKENS) {
                tokens[token_count++] = token_start;
                token_start = NULL;
            }
        } 
        else if (!token_start) {
            token_start = cursor;
        }
    }

    if (token_start && token_count < MAX_TOKENS && (!in_quotes || (cursor > token_start))) {
        *cursor = '\0';
        tokens[token_count++] = token_start;
    }

    return token_count;
}

void sigchld_handler(int sig) {
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0);
    errno = saved_errno;
}


int main() {

    int interactive = isatty(STDIN_FILENO);
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }


    while (1) {
        if (interactive) {
            printf("%s>", prompt);
        }

        if (fgets(line, MAX_LINE_LENGTH, stdin) == NULL) {
            break;
        }

        strcpy(originalLine, line);
        if (originalLine[strlen(originalLine) - 1] == '\n') {
            originalLine[strlen(originalLine) - 1] = '\0';
        }

        tokenize(line);

        if (debug_level > 0) {
            print_tokens();
        }
        
        char *input_file = NULL, *output_file = NULL;
        parse_command_features(&input_file, &output_file);

        char *args[MAX_TOKENS];
        int argc = 0;
        for (int i = 0; i < token_count; i++) {
            args[i] = tokens[i];
            argc++;
        }
        args[argc] = NULL;

        execute_command(argc, args, input_file, output_file);
    }
    return last_exit_status;
}