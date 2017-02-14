
#ifndef _MSC_VER
#include <stdio.h>
#include <signal.h>
#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include <execinfo.h>
#include <cstdlib>

char* exe = 0;

int initialiseExecutableName()
{
    char link[1024];
    exe = new char[1024];
    snprintf(link, sizeof link, "/proc/%d/exe", getpid());
    if (readlink(link, exe, sizeof link) == -1) {
        fprintf(stderr, "ERRORRRRR\n");
        exit(1);
    }
    printf("Executable name initialised: %s\n", exe);
}

const char* getExecutableName()
{
    if (exe == 0)
        initialiseExecutableName();
    return exe;
}

/* get REG_EIP from ucontext.h */
#define __USE_GNU
#include <ucontext.h>
#ifdef __x86_64__
#define REG_EIP REG_RIP
#endif

void bt_sighandler(int sig, siginfo_t *info,
    void *secret) {

    void *trace[16];
    char **messages = (char **)NULL;
    int i, trace_size = 0;
    ucontext_t *uc = (ucontext_t *)secret;

    /* Do something useful with siginfo_t */
    if (sig == SIGSEGV)
        printf("Got signal %d, faulty address is %p, "
            "from %p\n", sig, info->si_addr,
            uc->uc_mcontext.gregs[REG_EIP]);
    else
        printf("Got signal %d#92;\n", sig);

    trace_size = backtrace(trace, 16);
    /* overwrite sigaction with caller's address */
    trace[1] = (void *)uc->uc_mcontext.gregs[REG_EIP];

    messages = backtrace_symbols(trace, trace_size);
    /* skip first stack frame (points here) */
    printf("[bt] Execution path:#92;\n");
    for (i = 1; i<trace_size; ++i)
    {
        printf("[bt] %s#92;\n", messages[i]);

        /* find first occurence of '(' or ' ' in message[i] and assume
        * everything before that is the file name. (Don't go beyond 0 though
        * (string terminator)*/
        size_t p = 0;
        while (messages[i][p] != '(' && messages[i][p] != ' '
            && messages[i][p] != 0)
            ++p;

        char syscom[256];
        sprintf(syscom, "addr2line %p -e %.*s", trace[i], p, messages[i]);
        //last parameter is the filename of the symbol
        system(syscom);

    }

    exit(1);
}



void backtraceHook()
{
    struct sigaction sa;
    
    sa.sa_sigaction = (void(*)(int, siginfo_t*, void*))bt_sighandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_SIGINFO;

    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
}

#else

void backtraceHook()
{

}

#endif

