/*
 * ==============================================================================
 * Simulation: Harmless Process Memory Injection Trigger (trigger_ptrace.c)
 * ==============================================================================
 * Forks a dummy child worker process and invokes PTRACE_ATTACH and PTRACE_POKETEXT
 * to emulate code injection and process tampering under controlled conditions.
 *
 * Compilation: gcc -O2 trigger_ptrace.c -o trigger_ptrace
 * ==============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>

int main(int argc, char *argv[]) {
    printf("[*] Starting PTRACE Process Injection Simulation...\n");

    pid_t child = fork();

    if (child == -1) {
        perror("[-] fork failed");
        return 1;
    }

    if (child == 0) {
        /* Child Process: loops waiting for signals */
        printf("[*] [Child Process PID: %d] Running dummy target loop...\n", getpid());
        while (1) {
            sleep(1);
        }
        exit(0);
    } else {
        /* Parent Process: attaches to child and performs memory poke */
        sleep(1); /* Allow child to initialize */

        printf("[*] [Parent Process PID: %d] Invoking PTRACE_ATTACH on Target PID: %d...\n", getpid(), child);
        if (ptrace(PTRACE_ATTACH, child, NULL, NULL) < 0) {
            perror("[-] PTRACE_ATTACH failed");
            kill(child, SIGKILL);
            return 1;
        }

        int status;
        waitpid(child, &status, 0);

        if (WIFSTOPPED(status)) {
            printf("[+] Target process attached and stopped. Invoking PTRACE_POKETEXT...\n");

            /* Safely write dummy NOP instruction byte 0x90 at dummy address */
            unsigned long dummy_addr = 0x400000;
            unsigned long dummy_data = 0x90909090;

            long res = ptrace(PTRACE_POKETEXT, child, (void *)dummy_addr, (void *)dummy_data);
            if (res == -1 && errno != 0) {
                /* Even if memory is write-protected in child, the sys_enter_ptrace syscall fired */
                printf("[*] PTRACE_POKETEXT syscall intercepted by kernel (errno=%d).\n", errno);
            } else {
                printf("[+] PTRACE_POKETEXT succeeded.\n");
            }

            printf("[*] Detaching from target process...\n");
            ptrace(PTRACE_DETACH, child, NULL, NULL);
        }

        /* Clean up dummy child process */
        kill(child, SIGTERM);
        waitpid(child, NULL, 0);

        printf("[+] PTRACE injection simulation completed successfully.\n");
    }

    return 0;
}
