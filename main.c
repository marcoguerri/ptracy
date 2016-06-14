#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ptrace.h>

int 
main(int argc, char *argv[], char *envp[])
{

    pid_t pid;
    int status;

    pid = fork();
    if(pid < 0)
    {
        perror("fork: ");
        exit(1);
    }

    if(pid > 0)
    {
        pid = wait(&status);
        if(WIFSTOPPED(status)) 
            printf("Child was stopped with %s\n", sys_siglist[WSTOPSIG(status)]);
        ptrace(PTRACE_CONT, pid, NULL, NULL);
        
        pid = wait(&status);
        if(WIFEXITED(status))
            printf("Finished tracing\n");
        else
            printf("Child not exited?\n");
        return WEXITSTATUS(status);
    }
    else
    {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        if(argc < 2) 
        {
            fprintf(stderr, "A command must be provided\n");
            return 1;
        }
        char *const env[] = { "PATH=/bin", 0};
        int ret = execve(argv[1], argv+1, env);
        if(ret == -1) 
        {
            perror("execve: ");
            return -1;
        }
        return 8;
    }
    return 0;
}
