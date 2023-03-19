#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

int main(int argc, char **argv) {
    pid_t pid;
    char *search_val;
    long val;
    int count = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pid|name>\n", argv[0]);
        return 1;
    }

    if (isdigit(argv[1][0])) {
        pid = atoi(argv[1]);
    } else {
        // Find the PID of the process by name
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "pgrep %s", argv[1]);
        FILE *fp = popen(cmd, "r");
        if (!fp || fscanf(fp, "%d", &pid) != 1) {
            fprintf(stderr, "Failed to find process: %s\n", argv[1]);
            return 1;
        }
        pclose(fp);
    }

    printf("Attaching to process %d\n", pid);

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        perror("ptrace");
        return 1;
    }

    int status;
    waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "Process %d not stopped\n", pid);
        return 1;
    }

    printf("Process %d stopped\n", pid);

    while (count < 5) {
        printf("Enter a value to search for (q to quit): ");
        char input[256];
        fgets(input, sizeof(input), stdin);
        if (input[0] == 'q') {
            break;
        }

        if (sscanf(input, "%ld", &val) != 1) {
            search_val = input;
        } else {
            search_val = (char *)&val;
        }

        long addr = 0;
        int found = 0;
        while (1) {
            long value = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, NULL);
            if (value == -1 && errno) {
                perror("ptrace");
                break;
            }

            if (memcmp(&value, search_val, sizeof(val)) == 0) {
                printf("0x%016lx (+0x%lx): 0x%lx\n", addr, addr - (long)val, value);
                found = 1;
                count++;
                if (count >= 5) {
                    break;
                }
            }

            addr += sizeof(val);
        }

        if (!found) {
            printf("Value not found\n");
        }
    }

    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    return 0;
}
