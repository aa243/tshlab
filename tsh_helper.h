/*
 * tsh_helper.h: definitions and interfaces for tshlab
 *
 * tsh_helper.h defines enumerators and structs used in tshlab,
 * as well as helper routine interfaces for tshlab.
 *
 * All of the helper routines that will be called by a signal handler
 * are async-signal-safe.
 */

#ifndef __TSH_HELPER_H__
#define __TSH_HELPER_H__

#include <assert.h>
#include <stdbool.h>

#include "csapp.h"

#define MAXLINE_TSH 1024  // max line size
#define MAXARGS 128       // max args on a command line
#define MAXJOBS 16        // max jobs at any point in time
#define MAXJID 1 << 16    // max job ID

/*
 * Job states: FG (foreground), BG (background), ST (stopped),
 *             UNDEF (undefined)
 * Job state transitions and enabling actions:
 *     FG -> ST  : ctrl-z
 *     ST -> FG  : fg command
 *     ST -> BG  : bg command
 *     BG -> FG  : fg command
 * At most 1 job can be in the FG state.
 */

// Job states
typedef enum job_state
{
    UNDEF,
    FG,
    BG,
    ST
} job_state;

// Parseline return states
typedef enum parseline_return
{
    PARSELINE_FG,
    PARSELINE_BG,
    PARSELINE_EMPTY,
    PARSELINE_ERROR
} parseline_return;

// Builtin states for shell to execute
typedef enum builtin_state
{
    BUILTIN_NONE,
    BUILTIN_QUIT,
    BUILTIN_JOBS,
    BUILTIN_BG,
    BUILTIN_FG
} builtin_state;

struct job_t  // The job struct
{
    pid_t pid;                  // Job PID
    int jid;                    // Job ID [1, 2, ...] defined in tsh_helper.c
    job_state state;            // UNDEF, BG, FG, or ST
    char cmdline[MAXLINE_TSH];  // Command line
};

struct cmdline_tokens
{
    char text[MAXLINE_TSH];  // Modified text from command line
    int argc;                // Number of arguments
    char* argv[MAXARGS];     // The arguments list
    char* infile;            // The input file
    char* outfile;           // The output file
    builtin_state builtin;   // Indicates if argv[0] is a builtin command
};

// These variables are externally defined in tsh_helper.c.
extern char prompt[];     // Command line prompt (do not change)
extern bool verbose;      // If true, prints additional output
extern bool check_block;  // If true, check that signals are blocked

extern struct job_t job_list[MAXJOBS];  // The job list

/*
 * parseline takes in the command line and pointer to a token struct.
 * It parses the command line and populates the token struct
 * It returns the following values of enumerated type parseline_return:
 *   PARSELINE_EMPTY        if the command line is empty
 *   PARSELINE_BG           if the user has requested a BG job
 *   PARSELINE_FG           if the user has requested a FG job
 *   PARSELINE_ERROR        if cmdline is incorrectly formatted
 */
parseline_return parseline(const char* cmdline, struct cmdline_tokens* token);

/*
 * sigquit_handler terminates the shell due to SIGQUIT signal.
 */
void sigquit_handler(int sig);

/*
 * initjobs initializes the supplied job list.
 */
void initjobs(struct job_t* jl);

/*
 * addjob takes in a job list, a process ID, a job state, and the command line
 * and adds the pid, job ID, state, and cmdline into a job struct in
 * the job list. Returns true on success, and false otherwise.
 * See the job_t struct above for more details.
 */
bool addjob(struct job_t* jl, pid_t pid, job_state state, const char* cmdline);

/*
 * deletejob deletes the job with the supplied process ID from the job list.
 * It returns true if successful and false if no job with this pid is found.
 */
bool deletejob(struct job_t* jl, pid_t pid);

/*
 * fgpid returns the process ID of the foreground job in the
 * supplied job list.
 */
pid_t fgpid(struct job_t* jl);

/*
 * getjobpid takes in a job list and a process ID, and returns either
 * a pointer the job struct with the respective process ID, or
 * NULL if a job with the given process ID does not exist.
 */
struct job_t* getjobpid(struct job_t* jl, pid_t pid);

/*
 * getjobjid takes in a job list and a job ID, and returns either
 * a pointer the job struct with the respective job ID, or
 * NULL if a job with the given job ID does not exist.
 */
struct job_t* getjobjid(struct job_t* jl, int jid);

/*
 * pid2jid converts the supplied process ID into its corresponding
 * job ID in the job list.
 */
int pid2jid(struct job_t* jl, pid_t pid);

/*
 * listjobs prints the job list.
 */
void listjobs(struct job_t* jl, int output_fd);

/*
 * usage prints the usage of the tiny shell.
 */
void usage(void);

#endif
