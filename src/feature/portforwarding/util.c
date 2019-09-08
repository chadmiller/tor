#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#define SUBPROCESS_PRIVATE

#include "lib/smartlist_core/smartlist_core.h"
#include "lib/smartlist_core/smartlist_split.h"
#include "lib/container/smartlist.h"
#include "lib/string/util_string.h"
#include "lib/string/scanf.c"
#include "lib/string/printf.h"
#include "lib/process/env.h"
#include "lib/process/subprocess.h"
#include "lib/malloc/malloc.h"
#include "lib/log/util_bug.h"

#include "util.h"

/* DOCDOC */
static void
log_portfw_spawn_error_message(const char *buf,
                               const char *executable, int *child_status)
{
  /* Parse error message */
  int retval, child_state, saved_errno;
  retval = tor_sscanf(buf, SPAWN_ERROR_MESSAGE "%x/%x",
                      &child_state, &saved_errno);
  if (retval == 2) {
    log_warn(LD_GENERAL,
             "Failed to start child process \"%s\" in state %d: %s",
             executable, child_state, strerror(saved_errno));
    if (child_status)
      *child_status = 1;
  } else {
    /* Failed to parse message from child process, log it as a
       warning */
    log_warn(LD_GENERAL,
             "Unexpected message from port forwarding helper \"%s\": %s",
             executable, buf);
  }
}

/** Read from fd, and send lines to log at the specified log level.
 * Returns 1 if stream is closed normally, -1 if there is a error reading, and
 * 0 otherwise. Handles lines from tor-fw-helper and
 * tor_spawn_background() specially.
 */
static int
log_from_pipe(int fd, int severity, const char *executable,
              int *child_status)
{
  char buf[256];
  enum stream_status r;

  for (;;) {
    r = get_string_from_pipe(fd, buf, sizeof(buf) - 1);

    if (r == IO_STREAM_CLOSED) {
      return 1;
    } else if (r == IO_STREAM_EAGAIN) {
      return 0;
    } else if (r == IO_STREAM_TERM) {
      return -1;
    }

    tor_assert(r == IO_STREAM_OKAY);

    /* Check if buf starts with SPAWN_ERROR_MESSAGE */
    if (strcmpstart(buf, SPAWN_ERROR_MESSAGE) == 0) {
      log_portfw_spawn_error_message(buf, executable, child_status);
    } else {
      log_fn(severity, LD_GENERAL, "Port forwarding helper says: %s", buf);
    }
  }

  /* We should never get here */
  return -1;
}


#if 0
/** Reads from <b>fd</b> and stores input in <b>buf_out</b> making
 *  sure it's below <b>count</b> bytes.
 *  If the string has a trailing newline, we strip it off.
 *
 * This function is specifically created to handle input from managed
 * proxies, according to the pluggable transports spec. Make sure it
 * fits your needs before using it.
 *
 * Returns:
 * IO_STREAM_CLOSED: If the stream is closed.
 * IO_STREAM_EAGAIN: If there is nothing to read and we should check back
 *  later.
 * IO_STREAM_TERM: If something is wrong with the stream.
 * IO_STREAM_OKAY: If everything went okay and we got a string
 *  in <b>buf_out</b>. */
enum stream_status
get_string_from_pipe(int fd, char *buf_out, size_t count)
{
  ssize_t ret;

  tor_assert(count <= INT_MAX);

  ret = read(fd, buf_out, count);

  if (ret == 0)
    return IO_STREAM_CLOSED;
  else if (ret < 0 && errno == EAGAIN)
    return IO_STREAM_EAGAIN;
  else if (ret < 0)
    return IO_STREAM_TERM;

  if (buf_out[ret - 1] == '\n') {
    /* Remove the trailing newline */
    buf_out[ret - 1] = '\0';
  } else
    buf_out[ret] = '\0';

  return IO_STREAM_OKAY;
}

#endif

/** Parse a <b>line</b> from tor-fw-helper and issue an appropriate
 *  log message to our user. */
static void
handle_fw_helper_line(const char *executable, const char *line)
{
  smartlist_t *tokens = smartlist_new();
  char *message = NULL;
  char *message_for_log = NULL;
  const char *external_port = NULL;
  const char *internal_port = NULL;
  const char *result = NULL;
  int port = 0;
  int success = 0;

  if (strcmpstart(line, SPAWN_ERROR_MESSAGE) == 0) {
    /* We need to check for SPAWN_ERROR_MESSAGE again here, since it's
     * possible that it got sent after we tried to read it in log_from_pipe.
     *
     * XXX Ideally, we should be using one of stdout/stderr for the real
     * output, and one for the output of the startup code.  We used to do that
     * before cd05f35d2c.
     */
    int child_status;
    log_portfw_spawn_error_message(line, executable, &child_status);
    goto done;
  }

  smartlist_split_string(tokens, line, NULL,
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, -1);

  if (smartlist_len(tokens) < 5)
    goto err;

  if (strcmp(smartlist_get(tokens, 0), "tor-fw-helper") ||
      strcmp(smartlist_get(tokens, 1), "tcp-forward"))
    goto err;

  external_port = smartlist_get(tokens, 2);
  internal_port = smartlist_get(tokens, 3);
  result = smartlist_get(tokens, 4);

  if (smartlist_len(tokens) > 5) {
    /* If there are more than 5 tokens, they are part of [<message>].
       Let's use a second smartlist to form the whole message;
       strncat loops suck. */
    int i;
    int message_words_n = smartlist_len(tokens) - 5;
    smartlist_t *message_sl = smartlist_new();
    for (i = 0; i < message_words_n; i++)
      smartlist_add(message_sl, smartlist_get(tokens, 5+i));

    tor_assert(smartlist_len(message_sl) > 0);
    message = smartlist_join_strings(message_sl, " ", 0, NULL);

    /* wrap the message in log-friendly wrapping */
    tor_asprintf(&message_for_log, " ('%s')", message);

    smartlist_free(message_sl);
  }

  port = atoi(external_port);
  if (port < 1 || port > 65535)
    goto err;

  port = atoi(internal_port);
  if (port < 1 || port > 65535)
    goto err;

  if (!strcmp(result, "SUCCESS"))
    success = 1;
  else if (!strcmp(result, "FAIL"))
    success = 0;
  else
    goto err;

  if (!success) {
    log_warn(LD_GENERAL, "Tor was unable to forward TCP port '%s' to '%s'%s. "
             "Please make sure that your router supports port "
             "forwarding protocols (like NAT-PMP). Note that if '%s' is "
             "your ORPort, your relay will be unable to receive inbound "
             "traffic.", external_port, internal_port,
             message_for_log ? message_for_log : "",
             internal_port);
  } else {
    log_info(LD_GENERAL,
             "Tor successfully forwarded TCP port '%s' to '%s'%s.",
             external_port, internal_port,
             message_for_log ? message_for_log : "");
  }

  goto done;

 err:
  log_warn(LD_GENERAL, "tor-fw-helper sent us a string we could not "
           "parse (%s).", line);

 done:
  SMARTLIST_FOREACH(tokens, char *, cp, tor_free(cp));
  smartlist_free(tokens);
  tor_free(message);
  tor_free(message_for_log);
}

/** Read what tor-fw-helper has to say in its stdout and handle it
 *  appropriately */
static int
handle_fw_helper_output(const char *executable,
                        process_handle_t *process_handle)
{
  smartlist_t *fw_helper_output = NULL;
  enum stream_status stream_status = 0;

  fw_helper_output =
    tor_get_lines_from_handle(tor_process_get_stdout_pipe(process_handle),
                              &stream_status);
  if (!fw_helper_output) { /* didn't get any output from tor-fw-helper */
    /* if EAGAIN we should retry in the future */
    return (stream_status == IO_STREAM_EAGAIN) ? 0 : -1;
  }

  /* Handle the lines we got: */
  SMARTLIST_FOREACH_BEGIN(fw_helper_output, char *, line) {
    handle_fw_helper_line(executable, line);
    tor_free(line);
  } SMARTLIST_FOREACH_END(line);

  smartlist_free(fw_helper_output);

  return 0;
}

/** Spawn tor-fw-helper and ask it to forward the ports in
 *  <b>ports_to_forward</b>. <b>ports_to_forward</b> contains strings
 *  of the form "<external port>:<internal port>", which is the format
 *  that tor-fw-helper expects. */
void
tor_check_port_forwarding(const char *filename,
                          smartlist_t *ports_to_forward,
                          time_t now)
{
/* When fw-helper succeeds, how long do we wait until running it again */
#define TIME_TO_EXEC_FWHELPER_SUCCESS 300
/* When fw-helper failed to start, how long do we wait until running it again
 */
#define TIME_TO_EXEC_FWHELPER_FAIL 60

  /* Static variables are initialized to zero, so child_handle.status=0
   * which corresponds to it not running on startup */
  static process_handle_t *child_handle=NULL;

  static time_t time_to_run_helper = 0;
  int stderr_status, retval;
  int stdout_status = 0;

  tor_assert(filename);

  /* Start the child, if it is not already running */
  if ((!child_handle || child_handle->status != PROCESS_STATUS_RUNNING) &&
      time_to_run_helper < now) {
    /*tor-fw-helper cli looks like this: tor_fw_helper -p :5555 -p 4555:1111 */
    const char **argv; /* cli arguments */
    int args_n, status;
    int argv_index = 0; /* index inside 'argv' */

    tor_assert(smartlist_len(ports_to_forward) > 0);

    /* check for overflow during 'argv' allocation:
       (len(ports_to_forward)*2 + 2)*sizeof(char*) > SIZE_MAX ==
       len(ports_to_forward) > (((SIZE_MAX/sizeof(char*)) - 2)/2) */
    if ((size_t) smartlist_len(ports_to_forward) >
        (((SIZE_MAX/sizeof(char*)) - 2)/2)) {
      log_warn(LD_GENERAL,
               "Overflow during argv allocation. This shouldn't happen.");
      return;
    }
    /* check for overflow during 'argv_index' increase:
       ((len(ports_to_forward)*2 + 2) > INT_MAX) ==
       len(ports_to_forward) > (INT_MAX - 2)/2 */
    if (smartlist_len(ports_to_forward) > (INT_MAX - 2)/2) {
      log_warn(LD_GENERAL,
               "Overflow during argv_index increase. This shouldn't happen.");
      return;
    }

    /* Calculate number of cli arguments: one for the filename, two
       for each smartlist element (one for "-p" and one for the
       ports), and one for the final NULL. */
    args_n = 1 + 2*smartlist_len(ports_to_forward) + 1;
    argv = tor_calloc(args_n, sizeof(char *));

    argv[argv_index++] = filename;
    SMARTLIST_FOREACH_BEGIN(ports_to_forward, const char *, port) {
      argv[argv_index++] = "-p";
      argv[argv_index++] = port;
    } SMARTLIST_FOREACH_END(port);
    argv[argv_index] = NULL;

    /* Assume tor-fw-helper will succeed, start it later*/
    time_to_run_helper = now + TIME_TO_EXEC_FWHELPER_SUCCESS;

    if (child_handle) {
      tor_process_handle_destroy(child_handle, 1);
      child_handle = NULL;
    }

#ifdef _WIN32
    /* Passing NULL as lpApplicationName makes Windows search for the .exe */
    status = tor_spawn_background(NULL, argv, NULL, &child_handle);
#else
    status = tor_spawn_background(filename, argv, NULL, &child_handle);
#endif /* defined(_WIN32) */

    tor_free_((void*)argv);
    argv=NULL;

    if (PROCESS_STATUS_ERROR == status) {
      log_warn(LD_GENERAL, "Failed to start port forwarding helper %s",
              filename);
      time_to_run_helper = now + TIME_TO_EXEC_FWHELPER_FAIL;
      return;
    }

    log_info(LD_GENERAL,
             "Started port forwarding helper (%s) with pid '%d'",
             filename, tor_process_get_pid(child_handle));
  }

  /* If child is running, read from its stdout and stderr) */
  if (child_handle && PROCESS_STATUS_RUNNING == child_handle->status) {
    /* Read from stdout/stderr and log result */
    retval = 0;
#ifdef _WIN32
    stderr_status = log_from_handle(child_handle->stderr_pipe, LOG_INFO);
#else
    stderr_status = log_from_pipe(child_handle->stderr_pipe,
                                  LOG_INFO, filename, &retval);
#endif /* defined(_WIN32) */
    if (handle_fw_helper_output(filename, child_handle) < 0) {
      log_warn(LD_GENERAL, "Failed to handle fw helper output.");
      stdout_status = -1;
      retval = -1;
    }

    if (retval) {
      /* There was a problem in the child process */
      time_to_run_helper = now + TIME_TO_EXEC_FWHELPER_FAIL;
    }

    /* Combine the two statuses in order of severity */
    if (-1 == stdout_status || -1 == stderr_status)
      /* There was a failure */
      retval = -1;
#ifdef _WIN32
    else if (!child_handle || tor_get_exit_code(child_handle, 0, NULL) !=
             PROCESS_EXIT_RUNNING) {
      /* process has exited or there was an error */
      /* TODO: Do something with the process return value */
      /* TODO: What if the process output something since
       * between log_from_handle and tor_get_exit_code? */
      retval = 1;
    }
#else /* !(defined(_WIN32)) */
    else if (1 == stdout_status || 1 == stderr_status)
      /* stdout or stderr was closed, the process probably
       * exited. It will be reaped by waitpid() in main.c */
      /* TODO: Do something with the process return value */
      retval = 1;
#endif /* defined(_WIN32) */
    else
      /* Both are fine */
      retval = 0;

    /* If either pipe indicates a failure, act on it */
    if (0 != retval) {
      if (1 == retval) {
        log_info(LD_GENERAL, "Port forwarding helper terminated");
        child_handle->status = PROCESS_STATUS_NOTRUNNING;
      } else {
        log_warn(LD_GENERAL, "Failed to read from port forwarding helper");
        child_handle->status = PROCESS_STATUS_ERROR;
      }

      /* TODO: The child might not actually be finished (maybe it failed or
         closed stdout/stderr), so maybe we shouldn't start another? */
    }
  }
}

