#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/syscall.h>

#include "syscall.h"

#define SYSCALL_WAIT_ENTER   0
#define SYSCALL_WAIT_EXIT    1


int
main(int argc, char *argv[], char *envp[])
{

    pid_t pid;
    int status, fsa, ret;
    struct user_regs_struct regs;

    fsa = SYSCALL_WAIT_ENTER;
    pid = fork();
    if(pid < 0)
    {
        perror("fork: ");
        exit(EXIT_FAILURE);
    }

    if(pid > 0)
    {
        pid = wait(&status);
        if(WIFSTOPPED(status)) 
            printf("Child was stopped with %s\n", sys_siglist[WSTOPSIG(status)]);

        /* Tracee has just executed execve and has been suspended as if it had
         * received SIGTRAP. Let it resume until the next syscall */
        while(1)
        {
            /* Similar to PTRACE_CONT, but the tracee will be stopped at the
             * next entry to or exit from a system call. PTRACE_CONT actually
             * makes the tracee execute a single instruction. */
            if(ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1)
            {
                perror("ptrace");
                exit(EXIT_FAILURE);
            }

            pid = wait(&status);
            if(WIFEXITED(status))
            {
                printf("Child finished execution\n");
                break;
            }
            else if(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
            {
                if(fsa == SYSCALL_WAIT_ENTER)
                {
                    /* Child is invoking a syscall. Inspect registers and 
                     * return the syscall executed */
                    regs.rax = 0;
                    if(ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) 
                    {
                        perror("ptrace");
                        exit(EXIT_FAILURE);
                    }
                    printf("Child entered syscall %4llu, %s\n", 
                           regs.orig_rax,
                           syscall_table[regs.orig_rax].name_libc);
                    
                    fsa = SYSCALL_WAIT_EXIT;

                } else if(fsa == SYSCALL_WAIT_EXIT) {
                    fsa = SYSCALL_WAIT_ENTER;
                }
            } 
            else
            {
                /* Child changed status but it did not exit and it did not 
                 * stop due to SIGTRAP. It might have been a signal anyway. 
                 * Wait for it to exit. */
                fprintf(stderr,"Child changed to not supported status\n");
                if(ptrace(PTRACE_DETACH, pid, 0,0) == -1)
                {
                    perror("ptrace");
                    exit(EXIT_FAILURE);
                }
                waitpid(pid, &status, WEXITED);
                return 1;
            }
        } 
        
        return 0;
    }
    else
    {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        if(argc < 2) 
        {
            fprintf(stderr, "A command must be provided\n");
            return EXIT_FAILURE;
        }
        int ret = execve(argv[1], argv+1, envp);
        if(ret == -1) 
        {
            perror("execve: ");
            return EXIT_FAILURE;
        }
        /* Will never get here */
        assert(0 && "execve does not return on success");
        return EXIT_SUCCESS;
    }
    return 0;
}
