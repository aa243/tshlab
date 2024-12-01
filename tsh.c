
/*
 * tsh - A tiny shell program with job control
 * <The line above is not a sufficient documentation.
 *  You will need to write your program documentation.
 *  Follow the 15-213/18-213/15-513 style guide at
 *  http://www.cs.cmu.edu/~213/codeStyle.html.>
 */

#include "tsh_helper.h"

/*
 * If DEBUG is defined, enable contracts and printing on dbg_printf.
 */
#ifdef DEBUG
/* When debugging is enabled, these form aliases to useful functions */
#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_requires(...) assert(__VA_ARGS__)
#define dbg_assert(...) assert(__VA_ARGS__)
#define dbg_ensures(...) assert(__VA_ARGS__)
#else
/* When debugging is disabled, no code gets generated for these */
#define dbg_printf(...)
#define dbg_requires(...)
#define dbg_assert(...)
#define dbg_ensures(...)
#endif

/* Function prototypes */
void eval(const char* cmdline);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);
void sigquit_handler(int sig);

bool FG_IS_RUNNING = false;

/*
 * <Write main's function header documentation. What does main do?>
 * "Each function should be prefaced with a comment describing the purpose
 *  of the function (in a sentence or two), the function's arguments and
 *  return value, any error cases that are relevant to the caller,
 *  any pertinent side effects, and any assumptions that the function makes."
 */
int main(int argc, char** argv)
{
    char c;
    char cmdline[MAXLINE_TSH];  // Cmdline for fgets
    bool emit_prompt = true;    // Emit prompt (default)

    // Redirect stderr to stdout (so that driver will get all output
    // on the pipe connected to stdout)
    Dup2(STDOUT_FILENO, STDERR_FILENO);

    // Parse the command line
    while ((c = getopt(argc, argv, "hvp")) != EOF)
    {
        switch (c)
        {
            case 'h':  // Prints help message
                usage();
                break;
            case 'v':  // Emits additional diagnostic info
                verbose = true;
                break;
            case 'p':  // Disables prompt printing
                emit_prompt = false;
                break;
            default:
                usage();
        }
    }

    // Install the signal handlers
    Signal(SIGINT, sigint_handler);    // Handles ctrl-c
    Signal(SIGTSTP, sigtstp_handler);  // Handles ctrl-z
    Signal(SIGCHLD, sigchld_handler);  // Handles terminated or stopped child

    Signal(SIGTTIN, SIG_IGN);
    Signal(SIGTTOU, SIG_IGN);

    Signal(SIGQUIT, sigquit_handler);

    // Initialize the job list
    initjobs(job_list);

    // Execute the shell's read/eval loop
    while (true)
    {
        if (emit_prompt)
        {
            printf("%s", prompt);
            fflush(stdout);
        }

        if ((fgets(cmdline, MAXLINE_TSH, stdin) == NULL) && ferror(stdin))
        {
            app_error("fgets error");
        }

        if (feof(stdin))
        {
            // End of file (ctrl-d)
            printf("\n");
            fflush(stdout);
            fflush(stderr);
            return 0;
        }

        // Remove the trailing newline
        cmdline[strlen(cmdline) - 1] = '\0';

        // Evaluate the command line
        eval(cmdline);

        fflush(stdout);
    }

    return -1;  // control never reaches here
}

/* Handy guide for eval:
 *
 * If the user has requested a built-in command (quit, jobs, bg or fg),
 * then execute it immediately. Otherwise, fork a child process and
 * run the job in the context of the child. If the job is running in
 * the foreground, wait for it to terminate and then return.
 * Note: each child process must have a unique process group ID so that our
 * background children don't receive SIGINT (SIGTSTP) from the kernel
 * when we type ctrl-c (ctrl-z) at the keyboard.
 */

/*
 * <What does eval do?>
 */
void eval(const char* cmdline)
{
    parseline_return parse_result;
    struct cmdline_tokens token;
    sigset_t mask_all, mask_one, prev_one, prev_all;
    pid_t pid;

    // 解析命令行
    parse_result = parseline(cmdline, &token);
    Sigfillset(&mask_all);

    if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY)
    {
        return;
    }

    if (token.builtin == BUILTIN_QUIT)
    {
        exit(0);
    }
    else if (token.builtin == BUILTIN_JOBS)
    {
        int output_fd = STDOUT_FILENO;
        if (token.outfile)
        {
            output_fd = Open(token.outfile, O_WRONLY | O_CREAT | O_TRUNC, 0);
            if (output_fd < 0)
            {
                perror("open");
                return;
            }
        }

        Sigprocmask(SIG_BLOCK, &mask_all, &prev_all);
        listjobs(job_list, output_fd);
        Sigprocmask(SIG_SETMASK, &prev_all, NULL);
        return;
    }
    else if (token.builtin == BUILTIN_BG)
    {
        if (token.argc < 2)
        {
            printf("bg command requires PID or %%jobid argument\n");
            return;
        }
        struct job_t* job = NULL;
        Sigprocmask(SIG_BLOCK, &mask_all, &prev_all);
        if (token.argv[1][0] == '%')
        {
            int jid = atoi(&token.argv[1][1]);
            job = getjobjid(job_list, jid);
        }
        else
        {
            pid_t pid = atoi(token.argv[1]);
            job = getjobpid(job_list, pid);
        }
        Sigprocmask(SIG_SETMASK, &prev_all, NULL);

        if (job == NULL)
        {
            printf("No such job\n");
            return;
        }

        // 发送 SIGCONT 信号以继续运行被停止的作业
        if (kill(-job->pid, SIGCONT) < 0)
        {
            unix_error("kill (SIGCONT) error");
        }
        printf("[%d] (%d) %s\n", job->jid, job->pid, job->cmdline);

        Sigprocmask(SIG_BLOCK, &mask_all, &prev_all);
        job->state = BG;
        Sigprocmask(SIG_SETMASK, &prev_all, NULL);

        return;
    }
    else if (token.builtin == BUILTIN_FG)
    {
        Sigfillset(&mask_all);
        if (token.argc < 2)
        {
            printf("fg command requires PID or %%jobid argument\n");
            return;
        }
        struct job_t* job = NULL;
        Sigprocmask(SIG_BLOCK, &mask_all, &prev_all);
        if (token.argv[1][0] == '%')
        {
            int jid = atoi(&token.argv[1][1]);
            job = getjobjid(job_list, jid);
        }
        else
        {
            pid_t pid = atoi(token.argv[1]);
            job = getjobpid(job_list, pid);
        }
        Sigprocmask(SIG_SETMASK, &prev_all, NULL);

        if (job == NULL || job->state == UNDEF || job->state == FG ||
            job->state == BG)
        {
            printf("No such job or it is not in the ST state\n");
            return;
        }

        // 发送 SIGCONT 信号以继续运行被停止的作业
        if (kill(-job->pid, SIGCONT) < 0)
        {
            unix_error("kill (SIGCONT) error");
        }

        // 等待前台作业完成
        Sigprocmask(SIG_BLOCK, &mask_all, &prev_all);
        job->state = FG;
        FG_IS_RUNNING = true;
        while (FG_IS_RUNNING)
        {
            sigsuspend(&prev_all);
        }
        Sigprocmask(SIG_SETMASK, &prev_all, NULL);
        return;
    }

    // 阻塞 SIGCHLD 信号
    Sigemptyset(&mask_one);
    Sigaddset(&mask_one, SIGCHLD);
    Sigaddset(&mask_one, SIGINT);
    Sigaddset(&mask_one, SIGTSTP);
    Sigprocmask(SIG_BLOCK, &mask_one, &prev_one);

    if (parse_result == PARSELINE_FG)
        FG_IS_RUNNING = true;
    if ((pid = fork()) == 0)
    {  // 子进程
        // 恢复信号屏蔽字
        Sigprocmask(SIG_SETMASK, &prev_one, NULL);

        // 设置子进程组 ID
        Setpgid(0, 0);

        // 执行命令
        if (execve(token.argv[0], token.argv, environ) < 0)
        {
            printf("%s: Command not found\n", token.argv[0]);
            exit(0);
        }
    }

    // 父进程
    if (!token.builtin)
    {
        // 添加作业到作业列表
        if (FG_IS_RUNNING)
            addjob(job_list, pid, FG, cmdline);
        else
        {
            addjob(job_list, pid, BG, cmdline);
            printf("[%d] (%d) %s\n", pid2jid(job_list, pid), pid, cmdline);
        }

        // 等待前台作业完成
        while (FG_IS_RUNNING)
        {
            sigsuspend(&prev_one);
        }

        // 恢复信号屏蔽字
        Sigprocmask(SIG_SETMASK, &prev_one, NULL);
    }
}

/*****************
 * Signal handlers
 *****************/

/*
 * <What does sigchld_handler do?>
 */
void sigchld_handler(int sig)
{
    int olderrno = errno;
    pid_t pid;
    int status;
    sigset_t mask_all, prev_all;

    Sigfillset(&mask_all);

    // 使用 waitpid 回收所有已终止或停止的子进程
    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0)
    {
        Sigprocmask(SIG_BLOCK, &mask_all, &prev_all);
        // 判断子进程是否是前台进程
        if (pid == fgpid(job_list))
        {
            FG_IS_RUNNING = false;
        }

        if (WIFEXITED(status))
        {
            // 子进程正常终止
            deletejob(job_list, pid);  // 从作业列表中删除
        }
        else if (WIFSIGNALED(status))
        {
            // 子进程被信号终止
            struct job_t* job = getjobpid(job_list, pid);
            printf("Job [%d] (%d) terminated by signal %d\n", job->jid,
                   job->pid, WTERMSIG(status));
            deletejob(job_list, pid);  // 从作业列表中删除
        }
        else if (WIFSTOPPED(status))
        {
            // 子进程被信号停止

            struct job_t* job = getjobpid(job_list, pid);
            printf("Job [%d] (%d) stopped by signal %d\n", job->jid, job->pid,
                   WTERMSIG(status));
            job->state = ST;  // 修改作业状态为 ST
        }
        Sigprocmask(SIG_SETMASK, &prev_all, NULL);
    }

    errno = olderrno;
    return;
}

/*
 * <What does sigint_handler do?>
 */
void sigint_handler(int sig)
{
    sigset_t mask_all, prev_all;
    pid_t pid;

    // 初始化信号集，包含所有信号
    Sigfillset(&mask_all);

    // 阻塞所有信号
    Sigprocmask(SIG_BLOCK, &mask_all, &prev_all);

    pid = fgpid(job_list);  // 获取前台进程的 PID

    if (pid > 0)
    {
        kill(-pid, SIGINT);  // 向前台进程组发送 SIGINT 信号
    }

    // 恢复之前的信号屏蔽字
    Sigprocmask(SIG_SETMASK, &prev_all, NULL);
}

/*
 * <What does sigtstp_handler do?>
 */
void sigtstp_handler(int sig)
{
    sigset_t mask_all, prev_all;
    pid_t pid;

    // 初始化信号集，包含所有信号
    Sigfillset(&mask_all);

    // 阻塞所有信号
    Sigprocmask(SIG_BLOCK, &mask_all, &prev_all);

    pid = fgpid(job_list);  // 获取前台进程的 PID

    if (pid > 0)
    {
        kill(-pid, SIGTSTP);  // 向前台进程组发送 SIGTSTP 信号
    }

    // 恢复之前的信号屏蔽字
    Sigprocmask(SIG_SETMASK, &prev_all, NULL);
}
