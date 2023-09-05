#include "pam-utils.h"
#include "gdm-extensions/gdm-private-string-pam-extension.h"

#include <security/pam_appl.h>

#include <stdio.h>

static void
set_error (char **error, const char* error_msg)
{
  if (!error)
    return;

  *error = strdup (error_msg);
}

char *
argv_string_get (const char **argv, unsigned i)
{
  return strdup (argv[i]);
}

char *
get_user (pam_handle_t *pamh)
{
  const char *username;

  if (!pamh)
    return NULL;

  if (pam_get_item (pamh, PAM_USER, (const void **) &username) != PAM_SUCCESS)
    return NULL;

  return strdup (username);
}

char *
set_user (pam_handle_t *pamh, char *username)
{
  if (!pamh)
    return NULL;

  if (pam_set_item (pamh, PAM_USER, (const void *) username) != PAM_SUCCESS)
    return NULL;

  return NULL;
}

const char *
prompt_for_username (pam_handle_t *pamh, const char *prompt)
{
  const char *username = NULL;

  if (!pamh)
    return NULL;

  if (pam_get_user (pamh, &username, prompt) != PAM_SUCCESS)
    return NULL;

  return username;
}

const char *
get_module_name (pam_handle_t *pamh)
{
  const char *module_name;

  if (pam_get_item (pamh, PAM_SERVICE, (const void **) &module_name) != PAM_SUCCESS)
    return NULL;

  return module_name;
}

static struct pam_response *
send_msg_generic (pam_handle_t *pamh, const struct pam_message *pam_msg)
{
  const struct pam_conv *pc;
  struct pam_response *resp = NULL;

  if (pam_get_item (pamh, PAM_CONV, (const void **) &pc) != PAM_SUCCESS)
    return NULL;

  if (!pc || !pc->conv)
    return NULL;

  if (pc->conv (1, (const struct pam_message *[]){ pam_msg }, &resp,
                pc->appdata_ptr) != PAM_SUCCESS)
    return NULL;

  return resp;
}

struct pam_response *
send_msg (pam_handle_t *pamh, const char *msg, int style)
{
  const struct pam_message pam_msg = {
    .msg_style = style,
    .msg = msg,
  };

  return send_msg_generic (pamh, &pam_msg);
}

char *
gdm_private_string_protocol_send (pam_handle_t *pamh,
                                  const char   *proto_name,
                                  int           proto_version,
                                  const char   *value,
                                  char        **error)
{
  GdmPamExtensionStringProtocol request;
  GdmPamExtensionStringProtocol *response;
  struct pam_message prompt_message;
  struct pam_response *reply;
  char *ret_value;

  *error = NULL;

  GDM_PAM_EXTENSION_PRIVATE_STRING_REQUEST_INIT (&request, proto_name,
                                                 proto_version, value);
  GDM_PAM_EXTENSION_MESSAGE_TO_BINARY_PROMPT_MESSAGE (&request,
                                                      &prompt_message);
  reply = send_msg_generic (pamh, &prompt_message);

  if (!reply)
    {
      set_error (error, "PAM message not handled");
      return NULL;
    }

  response = GDM_PAM_EXTENSION_REPLY_TO_PRIVATE_STRING_RESPONSE (reply);

  if (!response->protocol_name ||
      strcmp (response->protocol_name, proto_name) != 0 ||
      response->version != proto_version)
    {
      set_error (error, "Protocol name or version mismatch");
      free (response->value);
      free (response);
      free (reply);
      return NULL;
    }

  ret_value = response->value; /* stolen from reply */
  free (response);
  free (reply);

  return ret_value;
}
