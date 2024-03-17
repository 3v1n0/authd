#include <security/_pam_types.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>

#include <security/pam_appl.h>
#include <sys/socket.h>

# define SSHD_PAM_SERVICE "sshd"

#define sshpam_const	const	/* LinuxPAM, OpenPAM, AIX */

# define PAM_MSG_MEMBER(msg, n, member) ((msg)[(n)]->member)

typedef pid_t sp_pthread_t;
#define pthread_exit    fake_pthread_exit
#define pthread_create  fake_pthread_create
#define pthread_cancel  fake_pthread_cancel
#define pthread_join    fake_pthread_join

typedef int SshPamDone;
#define SshPamError -1
#define SshPamNone 0
#define SshPamAuthenticated 1

struct pam_ctxt {
				sp_pthread_t     pam_thread;
				int              pam_psock;
				int              pam_csock;
				SshPamDone       pam_done;
};

typedef int SshPamDone;
#define SshPamError -1
#define SshPamNone 0
#define SshPamAuthenticated 1

static void sshpam_free_ctx(void *);
static struct pam_ctxt *cleanup_ctxt;

static u_int do_pam_account(void);
static int do_pam_putenv(char *name, char *value);

#ifndef UNSUPPORTED_POSIX_THREADS_HACK
/*
 * Simulate threads with processes.
 */

static int sshpam_thread_status = -1;
static __sighandler_t sshpam_oldsig;
static const char *service_name = SSHD_PAM_SERVICE;
static const char *service_path = NULL;

static void
sshpam_sigchld_handler(int sig)
{
	signal(SIGCHLD, SIG_DFL);
	if (cleanup_ctxt == NULL)
		return;	/* handler called after PAM cleanup, shouldn't happen */
	if (waitpid(cleanup_ctxt->pam_thread, &sshpam_thread_status, WNOHANG)
			<= 0) {
		/* PAM thread has not exitted, privsep slave must have */
		kill(cleanup_ctxt->pam_thread, SIGTERM);
		while (waitpid(cleanup_ctxt->pam_thread,
				&sshpam_thread_status, 0) == -1) {
			if (errno == EINTR)
				continue;
			return;
		}
	}
	if (WIFSIGNALED(sshpam_thread_status) &&
			WTERMSIG(sshpam_thread_status) == SIGTERM)
		return;	/* terminated by pthread_cancel */
	if (!WIFEXITED(sshpam_thread_status)) {
		printf("PAM: authentication thread exited unexpectedly\n");
		abort();
	}
	if (WEXITSTATUS(sshpam_thread_status) != 0) {
		printf("PAM: authentication thread exited uncleanly");
		abort();
	}
}

/* ARGSUSED */
static void
pthread_exit(void *value)
{
	_exit(0);
}

#define error(str, ...) printf("ERROR:" str "\n", ##__VA_ARGS__)
#define debug(str, ...) printf("DEBUG:" str "\n", ##__VA_ARGS__)
#define debug1(str, ...) printf("DEBUG1:" str "\n", ##__VA_ARGS__)
#define debug2(str, ...) printf("DEBUG2:" str "\n", ##__VA_ARGS__)
#define debug3(str, ...) printf("DEBUG3:" str "\n", ##__VA_ARGS__)
#define fatal(str, ...) { printf(str "\n", ##__VA_ARGS__); abort(); }

/* ARGSUSED */
static int
pthread_create(sp_pthread_t *thread, const void *attr,
		void *(*thread_start)(void *), void *arg)
{
	pid_t pid;
	struct pam_ctxt *ctx = arg;

	sshpam_thread_status = -1;
	switch ((pid = fork())) {
	case -1:
		error("fork(): %s", strerror(errno));
		return errno;
	case 0:
		close(ctx->pam_psock);
		ctx->pam_psock = -1;
		thread_start(arg);
		_exit(1);
	default:
		*thread = pid;
		close(ctx->pam_csock);
		ctx->pam_csock = -1;
		sshpam_oldsig = signal(SIGCHLD, sshpam_sigchld_handler);
		return (0);
	}
}

static int
pthread_cancel(sp_pthread_t thread)
{
	signal(SIGCHLD, sshpam_oldsig);
	return (kill(thread, SIGTERM));
}

/* ARGSUSED */
static int
pthread_join(sp_pthread_t thread, void **value)
{
	int status;

	if (sshpam_thread_status != -1)
		return (sshpam_thread_status);
	signal(SIGCHLD, sshpam_oldsig);
	while (waitpid(thread, &status, 0) == -1) {
		if (errno == EINTR)
			continue;
		fatal("%s: waitpid: %s", __func__, strerror(errno));
	}
	return (status);
}
#endif


static pam_handle_t *sshpam_handle = NULL;
static int sshpam_err = PAM_SYSTEM_ERR;
static int sshpam_authenticated = 0;
static int sshpam_session_open = 0;
static int sshpam_cred_established = 0;
static int sshpam_account_status = -1;
static int sshpam_maxtries_reached = 0;
static char **sshpam_env = NULL;
static const char *sshpam_password = NULL;
static char *sshpam_rhost = NULL;
static char *sshpam_laddr = NULL;

/*
 * Conversation function for authentication thread.
 */
static int
sshpam_thread_conv(int n, sshpam_const struct pam_message **msg,
		struct pam_response **resp, void *data)
{
	struct sshbuf *buffer;
	struct pam_ctxt *ctxt;
	struct pam_response *reply;
	int r, i;
	u_char status;

	debug3("PAM: %s entering, %d messages", __func__, n);
	*resp = NULL;

	if ((reply = calloc(n, sizeof(*reply))) == NULL)
		return PAM_CONV_ERR;

	for (i = 0; i < n; ++i) {
		switch (PAM_MSG_MEMBER(msg, i, msg_style)) {
		case PAM_PROMPT_ECHO_OFF:
			debug3("PROMPT OFF: %s", PAM_MSG_MEMBER(msg, i, msg));
			reply[i].resp = getpass(PAM_MSG_MEMBER(msg, i, msg));
			break;
		case PAM_PROMPT_ECHO_ON: {
			debug3("PROMPT ON: %s", PAM_MSG_MEMBER(msg, i, msg));
				char *buffer = NULL;
				size_t len;
				printf("%s: ", PAM_MSG_MEMBER(msg, i, msg));
				if (getline(&buffer, &len, stdin) == -1) {
					free(buffer);
					error("Can't get input");
					goto fail;
				}
				reply[i].resp = buffer;
				printf("Got input");
			}
			break;
		case PAM_ERROR_MSG:
			debug3("ERROR: %s", PAM_MSG_MEMBER(msg, i, msg));
			break;
		case PAM_TEXT_INFO:
			debug3("INFO: %s", PAM_MSG_MEMBER(msg, i, msg));
			break;
		default:
			goto fail;
		}
	}
	*resp = reply;
	return (PAM_SUCCESS);

 fail:
	for(i = 0; i < n; i++) {
		free(reply[i].resp);
	}
	free(reply);
	return (PAM_CONV_ERR);
}

static int force_pwchange = 0;

/*
 * Authentication thread.
 */
static void *
sshpam_thread(void *ctxtp)
{
	struct pam_ctxt *ctxt = ctxtp;
	struct sshbuf *buffer = NULL;
	struct pam_conv sshpam_conv;
	int r, flags = 0;
	extern char **environ;
	char **env_from_pam;
	u_int i;
	const char *pam_user;
	const char **ptr_pam_user = &pam_user;
	char *tz = getenv("TZ");

	sshpam_err = pam_get_item(sshpam_handle, PAM_USER,
			(sshpam_const void **)ptr_pam_user);
	if (sshpam_err != PAM_SUCCESS)
		goto auth_fail;

	environ[0] = NULL;
	if (tz != NULL)
		if (setenv("TZ", tz, 1) == -1)
			error("PAM: could not set TZ environment: %s",
					strerror(errno));

	sshpam_conv.conv = sshpam_thread_conv;
	sshpam_conv.appdata_ptr = ctxt;

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
			(const void *)&sshpam_conv);
	if (sshpam_err != PAM_SUCCESS)
		goto auth_fail;
	debug3("Starting PAM authentication");
	sshpam_err = pam_authenticate(sshpam_handle, flags);
	debug3("PAM Authenticate, returning %d (%s)", sshpam_err,
		pam_strerror(sshpam_handle, sshpam_err));
	if (sshpam_err != PAM_SUCCESS)
		goto auth_fail;

	if (!do_pam_account()) {
		sshpam_err = PAM_ACCT_EXPIRED;
		goto auth_fail;
	}
	if (force_pwchange) {
		sshpam_err = pam_chauthtok(sshpam_handle,
				PAM_CHANGE_EXPIRED_AUTHTOK);
		if (sshpam_err != PAM_SUCCESS)
			goto auth_fail;
	}

 auth_fail:
	debug3("Done with PAM, returning %d (%s)", sshpam_err,
		pam_strerror(sshpam_handle, sshpam_err));
	pthread_exit(NULL);

	return (NULL); /* Avoid warning for non-pthread case */
}

void
sshpam_thread_cleanup(void)
{
	struct pam_ctxt *ctxt = cleanup_ctxt;

	debug3("PAM: %s entering", __func__);
	if (ctxt != NULL && ctxt->pam_thread != 0) {
		pthread_cancel(ctxt->pam_thread);
		pthread_join(ctxt->pam_thread, NULL);
		close(ctxt->pam_psock);
		close(ctxt->pam_csock);
		memset(ctxt, 0, sizeof(*ctxt));
		cleanup_ctxt = NULL;
	}
}

static int
sshpam_null_conv(int n, sshpam_const struct pam_message **msg,
		struct pam_response **resp, void *data)
{
	debug3("PAM: %s entering, %d messages", __func__, n);
	return (PAM_CONV_ERR);
}

static struct pam_conv null_conv = { sshpam_null_conv, NULL };

static int
sshpam_store_conv(int n, sshpam_const struct pam_message **msg,
		struct pam_response **resp, void *data)
{
	struct pam_response *reply;
	int r, i;

	debug3("PAM: %s called with %d messages", __func__, n);
	*resp = NULL;

	if (n <= 0 || n > PAM_MAX_NUM_MSG)
		return (PAM_CONV_ERR);

	if ((reply = calloc(n, sizeof(*reply))) == NULL)
		return (PAM_CONV_ERR);

	for (i = 0; i < n; ++i) {
		switch (PAM_MSG_MEMBER(msg, i, msg_style)) {
		case PAM_ERROR_MSG:
			printf("ERROR: %s\n", PAM_MSG_MEMBER(msg, i, msg));
			reply[i].resp_retcode = PAM_SUCCESS;
			break;
		case PAM_TEXT_INFO:
			printf("INFO: %s\n", PAM_MSG_MEMBER(msg, i, msg));
			reply[i].resp_retcode = PAM_SUCCESS;
			break;
		default:
			goto fail;
		}
	}
	*resp = reply;
	return (PAM_SUCCESS);

 fail:
	for(i = 0; i < n; i++) {
		free(reply[i].resp);
	}
	free(reply);
	return (PAM_CONV_ERR);
}

static struct pam_conv store_conv = { sshpam_store_conv, NULL };

void
sshpam_cleanup(void)
{
	if (sshpam_handle == NULL)
		return;
	debug("PAM: cleanup");
	pam_set_item(sshpam_handle, PAM_CONV, (const void *)&null_conv);
	if (sshpam_session_open) {
		debug("PAM: closing session");
		pam_close_session(sshpam_handle, PAM_SILENT);
		sshpam_session_open = 0;
	}
	if (sshpam_cred_established) {
		debug("PAM: deleting credentials");
		pam_setcred(sshpam_handle, PAM_DELETE_CRED);
		sshpam_cred_established = 0;
	}
	sshpam_authenticated = 0;
	pam_end(sshpam_handle, sshpam_err);
	sshpam_handle = NULL;
}

static int
sshpam_init(const char *user)
{
	const char *pam_user;
	const char **ptr_pam_user = &pam_user;
	int r;

	if (sshpam_handle != NULL) {
		/* We already have a PAM context; check if the user matches */
		sshpam_err = pam_get_item(sshpam_handle,
				PAM_USER, (sshpam_const void **)ptr_pam_user);
		if (sshpam_err == PAM_SUCCESS && strcmp(user, pam_user) == 0)
			return (0);
		pam_end(sshpam_handle, sshpam_err);
		sshpam_handle = NULL;
	}
	debug("PAM: initializing \"%s\" for \"%s\"", service_name, user);
	if (service_path != NULL) {
		sshpam_err = pam_start_confdir(service_name, user, &store_conv, service_path, &sshpam_handle);
	} else {
		sshpam_err = pam_start(service_name, user, &store_conv, &sshpam_handle);
	}

	if (sshpam_err != PAM_SUCCESS) {
		pam_end(sshpam_handle, sshpam_err);
		sshpam_handle = NULL;
		return (-1);
	}

	sshpam_rhost = "fake-rhost";
	if (sshpam_rhost != NULL) {
		debug("PAM: setting PAM_RHOST to \"%s\"", sshpam_rhost);
		sshpam_err = pam_set_item(sshpam_handle, PAM_RHOST,
				sshpam_rhost);
		if (sshpam_err != PAM_SUCCESS) {
			pam_end(sshpam_handle, sshpam_err);
			sshpam_handle = NULL;
			return (-1);
		}
	}
	if (sshpam_laddr != NULL) {
		/* Put SSH_CONNECTION in the PAM environment too */
		if ((r = pam_putenv(sshpam_handle, "SSH_CONNECTION=fake conn 1")) != PAM_SUCCESS)
			debug("pam_putenv: %s", pam_strerror(sshpam_handle, r));
	}

	debug("PAM: setting PAM_TTY to \"ssh\"");
	sshpam_err = pam_set_item(sshpam_handle, PAM_TTY, "ssh");
	if (sshpam_err != PAM_SUCCESS) {
		pam_end(sshpam_handle, sshpam_err);
		sshpam_handle = NULL;
		return (-1);
	}
}

static void
expose_authinfo(const char *caller)
{
	/*
	 * Expose authentication information to PAM.
	 * The environment variable is versioned. Please increment the
	 * version suffix if the format of session_info changes.
	 */

	debug2("%s: auth information in SSH_AUTH_INFO_0", caller);
	do_pam_putenv("SSH_AUTH_INFO_0", "auth-info");
}

static void *
sshpam_init_ctx(const char *user)
{
	struct pam_ctxt *ctxt;
	int result, socks[2];

	debug3("PAM: %s entering", __func__);

	/* Initialize PAM */
	if (sshpam_init(user) == -1) {
		error("PAM: initialization failed");
		return (NULL);
	}

	expose_authinfo(__func__);
	ctxt = calloc(1, sizeof *ctxt);

	/* Start the authentication thread */
	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, socks) == -1) {
		error("PAM: failed create sockets: %s", strerror(errno));
		free(ctxt);
		return (NULL);
	}
	ctxt->pam_psock = socks[0];
	ctxt->pam_csock = socks[1];
	result = pthread_create(&ctxt->pam_thread, NULL, sshpam_thread, ctxt);
	if (result != 0) {
		error("PAM: failed to start authentication thread: %s",
				strerror(result));
		close(socks[0]);
		close(socks[1]);
		free(ctxt);
		return (NULL);
	}
	cleanup_ctxt = ctxt;
	return (ctxt);
}

// static int
// sshpam_query(void *ctx, char **name, char **info,
//     u_int *num, char ***prompts, u_int **echo_on)
// {
// 	struct sshbuf *buffer;
// 	struct pam_ctxt *ctxt = ctx;
// 	size_t plen;
// 	u_char type;
// 	char *msg;
// 	size_t len, mlen, nmesg = 0;
// 	int r;

// 	debug3("PAM: %s entering", __func__);
// 	if ((buffer = sshbuf_new()) == NULL)
// 		fatal("%s: sshbuf_new failed", __func__);
// 	*name = xstrdup("");
// 	*info = xstrdup("");
// 	*prompts = xmalloc(sizeof(char *));
// 	**prompts = NULL;
// 	plen = 0;
// 	*echo_on = xmalloc(sizeof(u_int));
// 	while (ssh_msg_recv(ctxt->pam_psock, buffer) == 0) {
// 		if (++nmesg > PAM_MAX_NUM_MSG)
// 			fatal_f("too many query messages");
// 		if ((r = sshbuf_get_u8(buffer, &type)) != 0 ||
// 		    (r = sshbuf_get_cstring(buffer, &msg, &mlen)) != 0)
// 			fatal("%s: buffer error: %s", __func__, ssh_err(r));
// 		switch (type) {
// 		case PAM_PROMPT_ECHO_ON:
// 		case PAM_PROMPT_ECHO_OFF:
// 			*num = 1;
// 			len = plen + mlen + 1;
// 			**prompts = xreallocarray(**prompts, 1, len);
// 			strlcpy(**prompts + plen, msg, len - plen);
// 			plen += mlen;
// 			**echo_on = (type == PAM_PROMPT_ECHO_ON);
// 			free(msg);
// 			sshbuf_free(buffer);
// 			return (0);
// 		case PAM_ERROR_MSG:
// 		case PAM_TEXT_INFO:
// 			/* accumulate messages */
// 			len = plen + mlen + 2;
// 			**prompts = xreallocarray(**prompts, 1, len);
// 			strlcpy(**prompts + plen, msg, len - plen);
// 			plen += mlen;
// 			strlcat(**prompts + plen, "\n", len - plen);
// 			plen++;
// 			free(msg);
// 			break;
// 		case PAM_ACCT_EXPIRED:
// 		case PAM_MAXTRIES:
// 			if (type == PAM_ACCT_EXPIRED)
// 				sshpam_account_status = 0;
// 			if (type == PAM_MAXTRIES)
// 				sshpam_set_maxtries_reached(1);
// 			/* FALLTHROUGH */
// 		case PAM_AUTH_ERR:
// 			debug3("PAM: %s", pam_strerror(sshpam_handle, type));
// 			if (**prompts != NULL && strlen(**prompts) != 0) {
// 				free(*info);
// 				*info = **prompts;
// 				**prompts = NULL;
// 				*num = 0;
// 				**echo_on = 0;
// 				ctxt->pam_done = SshPamError;
// 				free(msg);
// 				sshbuf_free(buffer);
// 				return 0;
// 			}
// 			/* FALLTHROUGH */
// 		case PAM_SUCCESS:
// 			if (**prompts != NULL) {
// 				/* drain any accumulated messages */
// 				debug("PAM: %s", **prompts);
// 				if ((r = sshbuf_put(loginmsg, **prompts,
// 				    strlen(**prompts))) != 0)
// 					fatal("%s: buffer error: %s",
// 					    __func__, ssh_err(r));
// 				free(**prompts);
// 				**prompts = NULL;
// 			}
// 			if (type == PAM_SUCCESS) {
// 				if (!sshpam_authctxt->valid ||
// 				    (sshpam_authctxt->pw->pw_uid == 0 &&
// 				    options.permit_root_login != PERMIT_YES))
// 					fatal("Internal error: PAM auth "
// 					    "succeeded when it should have "
// 					    "failed");
// 				import_environments(buffer);
// 				*num = 0;
// 				**echo_on = 0;
// 				ctxt->pam_done = SshPamAuthenticated;
// 				free(msg);
// 				sshbuf_free(buffer);
// 				return (0);
// 			}
// 			error("PAM: %s for %s%.100s from %.100s", msg,
// 			    sshpam_authctxt->valid ? "" : "illegal user ",
// 			    sshpam_authctxt->user, sshpam_rhost);
// 			/* FALLTHROUGH */
// 		default:
// 			*num = 0;
// 			**echo_on = 0;
// 			free(msg);
// 			ctxt->pam_done = SshPamError;
// 			sshbuf_free(buffer);
// 			return (-1);
// 		}
// 	}
// 	sshbuf_free(buffer);
// 	return (-1);
// }

// /*
//  * Returns a junk password of identical length to that the user supplied.
//  * Used to mitigate timing attacks against crypt(3)/PAM stacks that
//  * vary processing time in proportion to password length.
//  */
// static char *
// fake_password(const char *wire_password)
// {
// 	const char junk[] = "\b\n\r\177INCORRECT";
// 	char *ret = NULL;
// 	size_t i, l = wire_password != NULL ? strlen(wire_password) : 0;

// 	ret = malloc(l + 1);
// 	if (ret == NULL)
// 		return NULL;
// 	for (i = 0; i < l; i++)
// 		ret[i] = junk[i % (sizeof(junk) - 1)];
// 	ret[i] = '\0';
// 	return ret;
// }

#define KbdintResultFailure -1
#define KbdintResultSuccess 0
#define KbdintResultAgain 1

// /* XXX - see also comment in auth-chall.c:verify_response */
static int
sshpam_respond(void *ctx, u_int num)
{
	struct sshbuf *buffer;
	struct pam_ctxt *ctxt = ctx;
	char *fake;
	int r;

	debug2("PAM: %s entering, %u responses", __func__, num);
	switch (ctxt->pam_done) {
	case SshPamAuthenticated:
		sshpam_authenticated = 1;
		return KbdintResultSuccess;
	case SshPamNone:
		break;
	default:
		return KbdintResultFailure;
	}
	if (num != 1) {
		error("PAM: expected one response, got %u", num);
		return KbdintResultFailure;
	}
	return KbdintResultAgain;
}

static void
sshpam_free_ctx(void *ctxtp)
{
	struct pam_ctxt *ctxt = ctxtp;

	debug3("PAM: %s entering", __func__);
	sshpam_thread_cleanup();
	free(ctxt);
	/*
	 * We don't call sshpam_cleanup() here because we may need the PAM
	 * handle at a later stage, e.g. when setting up a session.  It's
	 * still on the cleanup list, so pam_end() *will* be called before
	 * the server process terminates.
	 */
}

// KbdintDevice sshpam_device = {
// 	"pam",
// 	sshpam_init_ctx,
// 	sshpam_query,
// 	sshpam_respond,
// 	sshpam_free_ctx
// };

// KbdintDevice mm_sshpam_device = {
// 	"pam",
// 	mm_sshpam_init_ctx,
// 	mm_sshpam_query,
// 	mm_sshpam_respond,
// 	mm_sshpam_free_ctx
// };

// /*
//  * This replaces auth-pam.c
//  */
// void
// start_pam(const char *user)
// {
// 	if (sshpam_init(user) == -1)
// 		fatal("PAM: initialisation failed");
// }

// void
// finish_pam(void)
// {
// 	sshpam_cleanup();
// }


static u_int
do_pam_account(void)
{
	debug("%s: called", __func__);
	if (sshpam_account_status != -1)
		return (sshpam_account_status);

	expose_authinfo(__func__);

	sshpam_err = pam_acct_mgmt(sshpam_handle, 0);
	debug3("PAM: %s pam_acct_mgmt = %d (%s)", __func__, sshpam_err,
			pam_strerror(sshpam_handle, sshpam_err));

	if (sshpam_err != PAM_SUCCESS && sshpam_err != PAM_NEW_AUTHTOK_REQD) {
		sshpam_account_status = 0;
		return (sshpam_account_status);
	}

	if (sshpam_err == PAM_NEW_AUTHTOK_REQD)
		force_pwchange = 1;

	sshpam_account_status = 1;
	return (sshpam_account_status);
}

void
do_pam_setcred(int init)
{
	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
			(const void *)&store_conv);
	if (sshpam_err != PAM_SUCCESS)
		fatal("PAM: failed to set PAM_CONV: %s",
				pam_strerror(sshpam_handle, sshpam_err));
	if (init) {
		debug("PAM: establishing credentials");
		sshpam_err = pam_setcred(sshpam_handle, PAM_ESTABLISH_CRED);
	} else {
		debug("PAM: reinitializing credentials");
		sshpam_err = pam_setcred(sshpam_handle, PAM_REINITIALIZE_CRED);
	}
	if (sshpam_err == PAM_SUCCESS) {
		sshpam_cred_established = 1;
		return;
	}
	if (sshpam_authenticated)
		{ fatal("PAM: pam_setcred(): %s",
				pam_strerror(sshpam_handle, sshpam_err));
		}
	else {
		debug("PAM: pam_setcred(): %s",
				pam_strerror(sshpam_handle, sshpam_err));
	}
}

static int
sshpam_tty_conv(int n, sshpam_const struct pam_message **msg,
		struct pam_response **resp, void *data)
{
	char input[PAM_MAX_MSG_SIZE];
	struct pam_response *reply;
	int i;

	debug3("PAM: %s called with %d messages", __func__, n);

	*resp = NULL;

	if (n <= 0 || n > PAM_MAX_NUM_MSG || !isatty(STDIN_FILENO))
		return (PAM_CONV_ERR);

	if ((reply = calloc(n, sizeof(*reply))) == NULL)
		return (PAM_CONV_ERR);

	for (i = 0; i < n; ++i) {
		switch (PAM_MSG_MEMBER(msg, i, msg_style)) {
		case PAM_PROMPT_ECHO_OFF:
			debug3("PROMPT OFF: %s", PAM_MSG_MEMBER(msg, i, msg));
			reply[i].resp = getpass(PAM_MSG_MEMBER(msg, i, msg));
			reply[i].resp_retcode = PAM_SUCCESS;
			break;
		case PAM_PROMPT_ECHO_ON:
		debug3("PROMPT ON: %s", PAM_MSG_MEMBER(msg, i, msg));
			fprintf(stderr, "%s\n", PAM_MSG_MEMBER(msg, i, msg));
			if (fgets(input, sizeof input, stdin) == NULL)
				input[0] = '\0';
			if ((reply[i].resp = strdup(input)) == NULL)
				goto fail;
			reply[i].resp_retcode = PAM_SUCCESS;
			break;
		case PAM_ERROR_MSG:
			fprintf(stderr, "PAM ERROR MSG: %s\n", PAM_MSG_MEMBER(msg, i, msg));
			reply[i].resp_retcode = PAM_SUCCESS;
			break;
		case PAM_TEXT_INFO:
			fprintf(stderr, "PAM INFO MSG: %s\n", PAM_MSG_MEMBER(msg, i, msg));
			reply[i].resp_retcode = PAM_SUCCESS;
			break;
		default:
			fprintf(stderr, "UNHANDLED MSG: %d\n", PAM_MSG_MEMBER(msg, i, msg_style));
			goto fail;
		}
	}
	*resp = reply;
	return (PAM_SUCCESS);

 fail:
	for(i = 0; i < n; i++) {
		free(reply[i].resp);
	}
	free(reply);
	return (PAM_CONV_ERR);
}

static struct pam_conv tty_conv = { sshpam_tty_conv, NULL };

/*
 * XXX this should be done in the authentication phase, but ssh1 doesn't
 * support that
 */
void
do_pam_chauthtok(void)
{
	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
			(const void *)&tty_conv);
	if (sshpam_err != PAM_SUCCESS)
		fatal("PAM: failed to set PAM_CONV: %s",
				pam_strerror(sshpam_handle, sshpam_err));
	debug("PAM: changing password");
	sshpam_err = pam_chauthtok(sshpam_handle, PAM_CHANGE_EXPIRED_AUTHTOK);
	if (sshpam_err != PAM_SUCCESS)
		fatal("PAM: pam_chauthtok(): %s",
				pam_strerror(sshpam_handle, sshpam_err));
}

void
do_pam_session()
{
	debug3("PAM: opening session");

	expose_authinfo(__func__);

	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
			(const void *)&store_conv);
	if (sshpam_err != PAM_SUCCESS)
		fatal("PAM: failed to set PAM_CONV: %s",
				pam_strerror(sshpam_handle, sshpam_err));
	sshpam_err = pam_open_session(sshpam_handle, 0);
	if (sshpam_err == PAM_SUCCESS)
		sshpam_session_open = 1;
	else {
		sshpam_session_open = 0;
		error("PAM: pam_open_session(): %s",
				pam_strerror(sshpam_handle, sshpam_err));
	}
}

int
is_pam_session_open(void)
{
	return sshpam_session_open;
}

/*
 * Set a PAM environment string. We need to do this so that the session
 * modules can handle things like Kerberos/GSI credentials that appear
 * during the ssh authentication process.
 */
static int
do_pam_putenv(char *name, char *value)
{
	int ret = 1;
	char *compound;
	size_t len;

	len = strlen(name) + strlen(value) + 2;
	compound = malloc(len);

	snprintf(compound, len, "%s=%s", name, value);
	ret = pam_putenv(sshpam_handle, compound);
	free(compound);

	return (ret);
}

char **
fetch_pam_child_environment(void)
{
	return sshpam_env;
}

char **
fetch_pam_environment(void)
{
	return (pam_getenvlist(sshpam_handle));
}

void
free_pam_environment(char **env)
{
	char **envp;

	if (env == NULL)
		return;

	for (envp = env; *envp; envp++)
		free(*envp);
	free(env);
}

/*
 * "Blind" conversation function for password authentication.  Assumes that
 * echo-off prompts are for the password and stores messages for later
 * display.
 */
static int
sshpam_passwd_conv(int n, sshpam_const struct pam_message **msg,
		struct pam_response **resp, void *data)
{
	return (PAM_SUCCESS);
// 	struct pam_response *reply;
// 	int r, i;
// 	size_t len;

// 	debug3("PAM: %s called with %d messages", __func__, n);

// 	*resp = NULL;

// 	if (n <= 0 || n > PAM_MAX_NUM_MSG)
// 		return (PAM_CONV_ERR);

// 	if ((reply = calloc(n, sizeof(*reply))) == NULL)
// 		return (PAM_CONV_ERR);

// 	for (i = 0; i < n; ++i) {
// 		switch (PAM_MSG_MEMBER(msg, i, msg_style)) {
// 		case PAM_PROMPT_ECHO_OFF:
// 			if (sshpam_password == NULL)
// 				goto fail;
// 			if ((reply[i].resp = strdup(sshpam_password)) == NULL)
// 				goto fail;
// 			reply[i].resp_retcode = PAM_SUCCESS;
// 			break;
// 		case PAM_ERROR_MSG:
// 		case PAM_TEXT_INFO:
// 			len = strlen(PAM_MSG_MEMBER(msg, i, msg));
// 			if (len > 0) {
// 				if ((r = sshbuf_putf(loginmsg, "%s\n",
// 				    PAM_MSG_MEMBER(msg, i, msg))) != 0)
// 					fatal("%s: buffer error: %s",
// 					    __func__, ssh_err(r));
// 			}
// 			if ((reply[i].resp = strdup("")) == NULL)
// 				goto fail;
// 			reply[i].resp_retcode = PAM_SUCCESS;
// 			break;
// 		default:
// 			goto fail;
// 		}
// 	}
// 	*resp = reply;
// 	return (PAM_SUCCESS);

//  fail:
// 	for(i = 0; i < n; i++) {
// 		free(reply[i].resp);
// 	}
// 	free(reply);
// 	return (PAM_CONV_ERR);
}

static struct pam_conv passwd_conv = { sshpam_passwd_conv, NULL };

// /*
//  * Attempt password authentication via PAM
//  */
// int
// sshpam_auth_passwd(Authctxt *authctxt, const char *password)
// {
// 	int flags = (options.permit_empty_passwd == 0 ?
// 	    PAM_DISALLOW_NULL_AUTHTOK : 0);
// 	char *fake = NULL;

// 	if (!options.use_pam || sshpam_handle == NULL)
// 		fatal("PAM: %s called when PAM disabled or failed to "
// 		    "initialise.", __func__);

// 	sshpam_password = password;
// 	sshpam_authctxt = authctxt;

// 	/*
// 	 * If the user logging in is invalid, or is root but is not permitted
// 	 * by PermitRootLogin, use an invalid password to prevent leaking
// 	 * information via timing (eg if the PAM config has a delay on fail).
// 	 */
// 	if (!authctxt->valid || (authctxt->pw->pw_uid == 0 &&
// 	    options.permit_root_login != PERMIT_YES))
// 		sshpam_password = fake = fake_password(password);

// 	sshpam_err = pam_set_item(sshpam_handle, PAM_CONV,
// 	    (const void *)&passwd_conv);
// 	if (sshpam_err != PAM_SUCCESS)
// 		fatal("PAM: %s: failed to set PAM_CONV: %s", __func__,
// 		    pam_strerror(sshpam_handle, sshpam_err));

// 	sshpam_err = pam_authenticate(sshpam_handle, flags);
// 	sshpam_password = NULL;
// 	free(fake);
// 	if (sshpam_err == PAM_MAXTRIES)
// 		sshpam_set_maxtries_reached(1);
// 	if (sshpam_err == PAM_SUCCESS && authctxt->valid) {
// 		debug("PAM: password authentication accepted for %.100s",
// 		    authctxt->user);
// 		return 1;
// 	} else {
// 		debug("PAM: password authentication failed for %.100s: %s",
// 		    authctxt->valid ? authctxt->user : "an illegal user",
// 		    pam_strerror(sshpam_handle, sshpam_err));
// 		return 0;
// 	}
// }

int main(int argc, char* argv[])
{
	struct pam_ctxt *ctxt;

	if (argc > 1)
		service_name = argv[1];

	if (argc > 2)
		service_path = argv[2];

	ctxt = sshpam_init_ctx(getenv("USER"));
	pthread_join(ctxt->pam_thread, NULL);
	sshpam_cleanup();

	close(ctxt->pam_psock);
	close(ctxt->pam_csock);
	memset(ctxt, 0, sizeof(*ctxt));
	free(ctxt);
	cleanup_ctxt = NULL;

	debug("PAM: Exiting with code %d (%s)", sshpam_err,
		pam_strerror(sshpam_handle, sshpam_err));

	return sshpam_err;
}
