
/*
 * 一个简单的在linux系统上运行的shell程序
 * 支持内建命令：quit, jobs, bg, fg
 * 支持在前台或者后台运行任意的程序
 * 支持输入输出重定向
 * 基于信号处理控制进程状态
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

struct job_t* string2job(char* string);

void bgfg(struct cmdline_tokens token);

bool built_in_commmand(struct cmdline_tokens token);

void waitfg();

void setFG(int pid);

/* FG_IS_RUNNING 表示是否有前台程序在运行；wifsignaled 和 wifstopped
 * 用来标记前台程序是被终止还是中断 */
bool FG_IS_RUNNING = false, wifsignaled = false, wifstopped = false;

/*
 * 对 shell 进行初始化并进入主循环
 * 参数是命令行的运行参数：-v, -p, -h
 * Usage: shell [-hvp]
 *  -h   print this message
 *  -v   print additional diagnostic information
 *  -p   do not emit a command prompt
 * 返回值是退出状态
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
 * 通过用户输入的 pid 或者 jid 字符串找到对应的 job
 * 输入：pid 或者 jid 字符串
 * 返回：对应的 job
 */
struct job_t* string2job(char* string)
{
    struct job_t* job = NULL;
    if (string[0] == '%')
    {
        int jid = atoi(&string[1]);
        job = getjobjid(job_list, jid);
    }
    else
    {
        pid_t pid = atoi(string);
        job = getjobpid(job_list, pid);
    }
    return job;
}

/*
 * 判断是否是内建命令
 * 如果是内建命令，执行内建命令并返回 true
 * 如果不是内建命令，返回 false
 */
bool built_in_commmand(struct cmdline_tokens token)
{
    sigset_t mask_all, prev_all;

    Sigfillset(&mask_all);

    if (token.builtin == BUILTIN_QUIT)
    {
        exit(0);
    }
    else if (token.builtin == BUILTIN_JOBS)
    {
        // 输出重定向
        int output_fd = STDOUT_FILENO;
        if (token.outfile)
        {
            output_fd = Open(token.outfile, O_WRONLY | O_CREAT | O_TRUNC, 0);
        }

        Sigprocmask(SIG_BLOCK, &mask_all, &prev_all);
        listjobs(job_list, output_fd);
        Sigprocmask(SIG_SETMASK, &prev_all, NULL);
        return true;
    }
    else if (token.builtin == BUILTIN_BG || token.builtin == BUILTIN_FG)
    {
        bgfg(token);
        return true;
    }
    else
        return false;
}

/*
 * bgfg 函数用来处理 bg 和 fg 命令
 * 输入：token，包含 bg 或 fg 命令的参数
 */
void bgfg(struct cmdline_tokens token)
{
    struct job_t* job = NULL;
    sigset_t mask_all, prev_all;

    Sigfillset(&mask_all);

    // 获得需要继续运行的 job
    Sigprocmask(SIG_BLOCK, &mask_all, &prev_all);
    job = string2job(token.argv[1]);
    Sigprocmask(SIG_SETMASK, &prev_all, NULL);

    if (job == NULL)
    {
        printf("No such job\n");
        return;
    }

    // 改变 job 的状态
    Sigprocmask(SIG_BLOCK, &mask_all, &prev_all);
    job->state = token.builtin == BUILTIN_BG ? BG : FG;
    FG_IS_RUNNING = token.builtin == BUILTIN_FG;
    Sigprocmask(SIG_SETMASK, &prev_all, NULL);

    // 发送 SIGCONT 信号以继续运行被停止的作业
    Kill(-job->pid, SIGCONT);
    if (token.builtin == BUILTIN_BG)
        printf("[%d] (%d) %s\n", job->jid, job->pid, job->cmdline);

    if (token.builtin == BUILTIN_FG)
    {
        waitfg();
    }

    return;
}

/*
 * waitfg 函数用来等待前台作业完成
 */
void waitfg()
{
    sigset_t mask_all, prev_all;
    Sigfillset(&mask_all);
    Sigprocmask(SIG_BLOCK, &mask_all, &prev_all);

    while (FG_IS_RUNNING)
    {
        Sigsuspend(&prev_all);  // 在等待时不需要屏蔽信号
    }

    Sigprocmask(SIG_SETMASK, &prev_all, NULL);
}

/*
 * 在进程停止运行后，检查其是否是前台进程，如果是，将 FG_IS_RUNNING 设置为 false
 * 输入：进程的pid
 */
void setFG(int pid)
{
    if (pid == fgpid(job_list))
    {
        FG_IS_RUNNING = false;
    }
}

/*
 * eval 函数用来解析命令行并执行命令
 * 输入：命令行字符串
 */
void eval(const char* cmdline)
{
    parseline_return parse_result;
    struct cmdline_tokens token;
    sigset_t mask_one, prev_one;
    pid_t pid;

    // 解析命令行
    parse_result = parseline(cmdline, &token);
    // Sigfillset(&mask_all);

    // 如果命令行为空或者解析错误，直接返回
    if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY)
    {
        return;
    }

    // 执行内建命令
    if (built_in_commmand(token))
    {
        return;
    }

    // 阻塞信号
    Sigemptyset(&mask_one);
    Sigaddset(&mask_one, SIGCHLD);
    Sigaddset(&mask_one, SIGINT);
    Sigaddset(&mask_one, SIGTSTP);
    Sigprocmask(SIG_BLOCK, &mask_one, &prev_one);

    // 设置前台运行标志
    if (parse_result == PARSELINE_FG)
        FG_IS_RUNNING = true;

    // 创建子进程来运行程序
    if ((pid = Fork()) == 0)
    {  // 子进程
        // 恢复信号屏蔽字
        Sigprocmask(SIG_SETMASK, &prev_one, NULL);

        // 设置子进程组 ID
        Setpgid(0, 0);

        // 输入重定向
        if (token.infile)
        {
            int input_fd = Open(token.infile, O_RDONLY, 0);

            Dup2(input_fd, STDIN_FILENO);
            Close(input_fd);
        }

        // 输出重定向
        if (token.outfile)
        {
            int output_fd =
                Open(token.outfile, O_WRONLY | O_CREAT | O_TRUNC, 0);
            Dup2(output_fd, STDOUT_FILENO);
            Close(output_fd);
        }

        // 执行命令
        Execve(token.argv[0], token.argv, environ);
    }

    // 父进程
    if (FG_IS_RUNNING)  // 前台
    {
        addjob(job_list, pid, FG, cmdline);

        // 等待前台作业完成
        while (FG_IS_RUNNING)
        {
            Sigsuspend(&prev_one);
        }

        // 被信号终止
        if (wifsignaled)
        {
            struct job_t* job = getjobpid(job_list, pid);
            printf("Job [%d] (%d) terminated by signal %d\n", job->jid,
                   job->pid, SIGINT);
            deletejob(job_list, pid);
            wifsignaled = false;
        }

        // 被信号停止
        if (wifstopped)
        {
            struct job_t* job = getjobpid(job_list, pid);
            printf("Job [%d] (%d) stopped by signal %d\n", job->jid, job->pid,
                   SIGTSTP);
            job->state = ST;
            wifstopped = false;
        }
    }
    else  // 后台
    {
        addjob(job_list, pid, BG, cmdline);
        printf("[%d] (%d) %s\n", pid2jid(job_list, pid), pid, cmdline);
    }

    // 恢复信号屏蔽字
    Sigprocmask(SIG_SETMASK, &prev_one, NULL);
}

/*****************
 * Signal handlers
 *****************/

/*
 * 处理 SIGCHLD 信号
 * 子进程正常停止，则从工作列表中删除
 * 子进程被信号终止，则标记 wifsignaled 为 true
 * 子进程被信号停止，则标记 wifstopped 为 true
 * 如果是前台进程被停止，则标记 FG_IS_RUNNING 为 false
 */
void sigchld_handler(int sig)
{
    int olderrno = errno;
    pid_t pid;
    int status;
    sigset_t mask_all, prev_all;

    Sigfillset(&mask_all);

    // 使用 waitpid 回收所有已终止或停止的子进程
    // 非阻塞回收，且记录中止的子进程的状态
    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0)
    {
        Sigprocmask(SIG_BLOCK, &mask_all, &prev_all);

        if (WIFEXITED(status))
        {
            // 子进程正常终止
            setFG(pid);

            deletejob(job_list, pid);
        }
        else if (WIFSIGNALED(status))
        {
            // 子进程被信号终止
            setFG(pid);

            wifsignaled = true;
        }
        else if (WIFSTOPPED(status))
        {
            // 子进程被信号停止
            setFG(pid);

            wifstopped = true;
        }
        Sigprocmask(SIG_SETMASK, &prev_all, NULL);
    }

    errno = olderrno;
    return;
}

/*
 * 处理 SIGINT 信号
 * 向前台进程组发送 SIGINT 信号
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
        Kill(-pid, SIGINT);  // 向前台进程组发送 SIGINT 信号
    }

    // 恢复之前的信号屏蔽字
    Sigprocmask(SIG_SETMASK, &prev_all, NULL);
}

/*
 * 处理 SIGTSTP 信号
 * 向前台进程组发送 SIGTSTP 信号
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
        Kill(-pid, SIGTSTP);  // 向前台进程组发送 SIGTSTP 信号
    }

    // 恢复之前的信号屏蔽字
    Sigprocmask(SIG_SETMASK, &prev_all, NULL);
}
