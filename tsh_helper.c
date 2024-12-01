/* tsh_helper.c
 * helper routines for tshlab
 */

#include "tsh_helper.h"

/* Global variables */
extern char** environ;    // Defined in libc
char prompt[] = "tsh> ";  // Command line prompt (do not change)
bool verbose = false;     // If true, prints additional output
bool check_block = true;  // If true, check that signals are blocked
int nextjid = 1;          // Next job ID to allocate
char sbuf[MAXLINE_TSH];   // For composing sprintf messages

// Parsing states, used for parseline
typedef enum parse_state
{
    ST_NORMAL,
    ST_INFILE,
    ST_OUTFILE
} parse_state;

struct job_t job_list[MAXJOBS];  // The job list

/*
 * parseline - Parse the command line and build the argv array.
 *
 *   cmdline:  The command line, in the form:
 *
 *                command [arguments...] [< infile] [> oufile] [&]
 *
 *   token:    Pointer to a cmdline_tokens structure. The elements of this
 *             structure will be populated with the parsed tokens. Characters
 *             enclosed in single or double quotes are treated as a single
 *             argument.
 *
 * Returns:
 *   PARSELINE_EMPTY:        if the command line is empty
 *   PARSELINE_BG:           if the user has requested a BG job
 *   PARSELINE_FG:           if the user has requested a FG job
 *   PARSELINE_ERROR:        if cmdline is incorrectly formatted
 *
 */
parseline_return parseline(const char* cmdline, struct cmdline_tokens* token)
{
    const char delims[] = " \t\r\n";  // argument delimiters (white-space)
    char* buf;                        // ptr that traverses command line
    char* next;                       // ptr to the end of the current arg
    char* endbuf;                     // ptr to end of cmdline string

    parse_state parsing_state;  // indicates if the next token is the
                                // input or output file

    if (cmdline == NULL)
    {
        fprintf(stderr, "Error: command line is NULL\n");
        return PARSELINE_EMPTY;
    }

    strncpy(token->text, cmdline, MAXLINE_TSH);

    buf = token->text;
    endbuf = token->text + strlen(token->text);

    // initialize default values
    token->argc = 0;
    token->infile = NULL;
    token->outfile = NULL;

    /* Build the argv list */
    parsing_state = ST_NORMAL;

    while (buf < endbuf)
    {
        /* Skip the white-spaces */
        buf += strspn(buf, delims);
        if (buf >= endbuf)
            break;

        /* Check for I/O redirection specifiers */
        if (*buf == '<')
        {
            if (token->infile)  // infile already exists
            {
                fprintf(stderr, "Error: Ambiguous I/O redirection\n");
                return PARSELINE_ERROR;
            }
            parsing_state = ST_INFILE;
            buf++;
            continue;
        }

        else if (*buf == '>')
        {
            if (token->outfile)  // outfile already exists
            {
                fprintf(stderr, "Error: Ambiguous I/O redirection\n");
                return PARSELINE_ERROR;
            }
            parsing_state = ST_OUTFILE;
            buf++;
            continue;
        }

        else if (*buf == '\'' || *buf == '\"')
        {
            /* Detect quoted tokens */
            buf++;
            next = strchr(buf, *(buf - 1));
        }

        else
        {
            /* Find next delimiter */
            next = buf + strcspn(buf, delims);
        }

        if (next == NULL)
        {
            /* Returned by strchr(); this means that the closing
               quote was not found. */
            fprintf(stderr, "Error: unmatched %c.\n", *(buf - 1));
            return PARSELINE_ERROR;
        }

        /* Terminate the token */
        *next = '\0';

        /* Record the token as either the next argument or the i/o file */
        switch (parsing_state)
        {
            case ST_NORMAL:
                token->argv[token->argc] = buf;
                token->argc = token->argc + 1;
                break;
            case ST_INFILE:
                token->infile = buf;
                break;
            case ST_OUTFILE:
                token->outfile = buf;
                break;
            default:
                fprintf(stderr, "Error: Ambiguous I/O redirection\n");
                return PARSELINE_ERROR;
        }
        parsing_state = ST_NORMAL;

        /* Check if argv is full */
        if (token->argc >= MAXARGS - 1)
            break;

        buf = next + 1;
    }

    if (parsing_state != ST_NORMAL)  // buf ends with < or >
    {
        fprintf(stderr, "Error: must provide file name for redirection\n");
        return PARSELINE_ERROR;
    }

    /* The argument list must end with a NULL pointer */
    token->argv[token->argc] = NULL;

    if (token->argc == 0) /* ignore blank line */
    {
        return PARSELINE_EMPTY;
    }

    if ((strcmp(token->argv[0], "quit")) == 0) /* quit command */
    {
        token->builtin = BUILTIN_QUIT;
    }
    else if ((strcmp(token->argv[0], "jobs")) == 0) /* jobs command */
    {
        token->builtin = BUILTIN_JOBS;
    }
    else if ((strcmp(token->argv[0], "bg")) == 0) /* bg command */
    {
        token->builtin = BUILTIN_BG;
    }
    else if ((strcmp(token->argv[0], "fg")) == 0) /* fg command */
    {
        token->builtin = BUILTIN_FG;
    }
    else
    {
        token->builtin = BUILTIN_NONE;
    }

    // Returns 1 if job runs on background; 0 if job runs on foreground

    if (*token->argv[(token->argc) - 1] == '&')
    {
        token->argv[--(token->argc)] = NULL;
        return PARSELINE_BG;
    }
    else
    {
        return PARSELINE_FG;
    }
}

/*****************
 * Signal handlers
 *****************/

void sigquit_handler(int sig)
{
    Sio_error("Terminating after receipt of SIGQUIT signal\n");
}

/*********************
 * End signal handlers
 *********************/

/***********************************************
 * Helper routines that manipulate the job list
 **********************************************/

/* check_blocked - Make sure that signals are blocked */
static void check_blocked()
{
    if (!check_block)
        return;
    sigset_t currmask;
    Sigprocmask(SIG_SETMASK, NULL, &currmask);
    if (!sigismember(&currmask, SIGCHLD))
    {
        Sio_puts("WARNING: SIGCHLD not set\n");
    }
    if (!sigismember(&currmask, SIGINT))
    {
        Sio_puts("WARNING: SIGINT not set\n");
    }
    if (!sigismember(&currmask, SIGTSTP))
    {
        Sio_puts("WARNING: SIGTSTP not set\n");
    }
}

/* clearjob - Clear the entries in a job struct */
static void clearjob(struct job_t* job)
{
    job->pid = 0;
    job->jid = 0;
    job->state = UNDEF;
    job->cmdline[0] = '\0';
}

/* initjobs - Initialize the job list */
void initjobs(struct job_t* jl)
{
    int i;

    for (i = 0; i < MAXJOBS; i++)
    {
        clearjob(&jl[i]);
    }
}

/* maxjid - Returns largest allocated job ID */
static int maxjid(struct job_t* jl)
{
    check_blocked();
    int i, max = 0;

    for (i = 0; i < MAXJOBS; i++)
    {
        if (jl[i].jid > max)
        {
            max = jl[i].jid;
        }
    }
    return max;
}

/* addjob - Add a job to the job list */
bool addjob(struct job_t* jl, pid_t pid, job_state state, const char* cmdline)
{
    check_blocked();
    int i;

    if (pid < 1)
    {
        return false;
    }

    for (i = 0; i < MAXJOBS; i++)
    {
        if (jl[i].pid == 0)
        {
            jl[i].pid = pid;
            jl[i].state = state;
            jl[i].jid = nextjid++;
            if (nextjid > MAXJOBS)
            {
                nextjid = 1;
            }
            strcpy(jl[i].cmdline, cmdline);
            if (verbose)
            {
                printf("Added job [%d] %d %s\n", job_list[i].jid,
                       job_list[i].pid, job_list[i].cmdline);
            }
            return true;
        }
    }
    printf("Tried to create too many jobs\n");
    return false;
}

/* deletejob - Delete a job whose PID=pid from the job list */
bool deletejob(struct job_t* jl, pid_t pid)
{
    check_blocked();
    int i;

    if (pid < 1)
    {
        if (verbose)
        {
            Sio_puts("deletejob: Invalid pid\n");
        }
        return false;
    }

    for (i = 0; i < MAXJOBS; i++)
    {
        if (jl[i].pid == pid)
        {
            clearjob(&jl[i]);
            nextjid = maxjid(jl) + 1;
            return true;
        }
    }
    if (verbose)
    {
        Sio_puts("deletejob: Invalid pid\n");
    }
    return false;
}

/* fgpid - Return PID of current foreground job, 0 if no such job */
pid_t fgpid(struct job_t* jl)
{
    check_blocked();
    int i;

    for (i = 0; i < MAXJOBS; i++)
    {
        if (jl[i].state == FG)
        {
            return jl[i].pid;
        }
    }
    if (verbose)
    {
        Sio_puts("fgpid: No foreground job found\n");
    }
    return 0;
}

/* getjobpid  - Find a job (by PID) on the job list */
struct job_t* getjobpid(struct job_t* jl, pid_t pid)
{
    check_blocked();
    int i;

    if (pid < 1)
    {
        if (verbose)
        {
            Sio_puts("getjobpid: Invalid pid\n");
        }
        return NULL;
    }

    for (i = 0; i < MAXJOBS; i++)
    {
        if (jl[i].pid == pid)
        {
            return &jl[i];
        }
    }
    if (verbose)
    {
        Sio_puts("getjobpid: Invalid pid\n");
    }

    return NULL;
}

/* getjobjid  - Find a job (by JID) on the job list */
struct job_t* getjobjid(struct job_t* jl, int jid)
{
    check_blocked();
    int i;

    if (jid < 1)
    {
        if (verbose)
        {
            Sio_puts("getjobjid: Invalid jid\n");
        }
        return NULL;
    }

    for (i = 0; i < MAXJOBS; i++)
    {
        if (jl[i].jid == jid)
        {
            return &jl[i];
        }
    }
    if (verbose)
    {
        Sio_puts("getjobjid: Invalid jid\n");
    }
    return NULL;
}

/* pid2jid - Map process ID to job ID */
int pid2jid(struct job_t* jl, pid_t pid)
{
    check_blocked();
    int i;

    if (pid < 1)
    {
        if (verbose)
        {
            Sio_puts("pid2jid: Invalid pid\n");
        }
        return 0;
    }
    for (i = 0; i < MAXJOBS; i++)
    {
        if (jl[i].pid == pid)
        {
            return jl[i].jid;
        }
    }
    if (verbose)
    {
        Sio_puts("pid2jid: Invalid pid\n");
    }
    return 0;
}

/* listjobs - Print the job list */
void listjobs(struct job_t* jl, int output_fd)
{
    check_blocked();
    int i;
    char buf[MAXLINE_TSH + 1];

    for (i = 0; i < MAXJOBS; i++)
    {
        memset(buf, '\0', MAXLINE_TSH + 1);
        if (jl[i].pid != 0)
        {
            sprintf(buf, "[%d] (%d) ", jl[i].jid, jl[i].pid);
            if (write(output_fd, buf, strlen(buf)) < 0)
            {
                fprintf(stderr, "Error writing to output file\n");
                exit(EXIT_FAILURE);
            }
            memset(buf, '\0', MAXLINE_TSH + 1);
            switch (jl[i].state)
            {
                case BG:
                    sprintf(buf, "Running    ");
                    break;
                case FG:
                    sprintf(buf, "Foreground ");
                    break;
                case ST:
                    sprintf(buf, "Stopped    ");
                    break;
                default:
                    sprintf(buf, "listjobs: Internal error: job[%d].state=%d ",
                            i, jl[i].state);
            }

            if (write(output_fd, buf, strlen(buf)) < 0)
            {
                fprintf(stderr, "Error writing to output file\n");
                exit(EXIT_FAILURE);
            }

            memset(buf, '\0', MAXLINE_TSH + 1);
            sprintf(buf, "%s\n", jl[i].cmdline);
            if (write(output_fd, buf, strlen(buf)) < 0)
            {
                fprintf(stderr, "Error writing to output file\n");
                exit(EXIT_FAILURE);
            }
        }
    }
}
/******************************
 * end job list helper routines
 ******************************/

/***********************
 * Other helper routines
 ***********************/

/*
 * usage - print a help message
 */
void usage(void)
{
    printf("Usage: shell [-hvp]\n");
    printf("   -h   print this message\n");
    printf("   -v   print additional diagnostic information\n");
    printf("   -p   do not emit a command prompt\n");
    exit(EXIT_FAILURE);
}
