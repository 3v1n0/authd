#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <security/pam_appl.h>

#include "gdm-extensions/gdm-private-string-pam-extension.h"

#include <stdio.h>

extern int go_handle_pam_message (struct pam_message *,
                                  unsigned char **reply);

static char pam_extension_environment_block[_POSIX_ARG_MAX];
static const char **supported_extensions = NULL;

static inline int
conversation_handler (int                        n_messages,
                      const struct pam_message **messages,
                      struct pam_response      **responses,
                      void                      *data)
{
  struct pam_response *replies;
  int retcode = PAM_SUCCESS;

  replies = (struct pam_response *) calloc (n_messages,
                                            sizeof (struct pam_response));

  for (int i = 0; i < n_messages; ++i)
    {
      replies[i].resp_retcode = go_handle_pam_message (
        (struct pam_message *) messages[i],
        (unsigned char **) &replies[i].resp);

      if (replies[i].resp_retcode != PAM_SUCCESS)
        {
          retcode = replies[i].resp_retcode;

          for (int j = 0; j <= i; j++)
            free (replies[j].resp);

          break;
        }
    }

  if (retcode != PAM_SUCCESS)
    {
      free (replies);
      *responses = NULL;
      return retcode;
    }

  *responses = replies;
  return PAM_SUCCESS;
}

static inline pam_handle_t *
init_handle (const char *service_name, const char *user, const char *confdir)
{
  pam_handle_t *pamh;
  struct pam_conv pam_conversation = { .conv = conversation_handler };

  if (pam_start_confdir (service_name, user,
                         &pam_conversation, confdir, &pamh) != 0)
    return NULL;

  return pamh;
}

static inline void
advertise_supported_pam_extensions (const char *extensions[])
{
  GDM_PAM_EXTENSION_ADVERTISE_SUPPORTED_EXTENSIONS (
    pam_extension_environment_block, extensions);

  supported_extensions = extensions;
}

static inline const char *
get_gdm_string_protocol_value (const struct pam_message *query,
                               const char              **proto_name,
                               int                      *proto_version)
{
  GdmPamExtensionMessage *extended_message;

  if (!supported_extensions)
    {
      fprintf (stderr, "No PAM extensions supported");
      return NULL;
    }

  extended_message = GDM_PAM_EXTENSION_MESSAGE_FROM_PAM_MESSAGE (query);

  if (GDM_PAM_EXTENSION_MESSAGE_TRUNCATED (extended_message))
    {
      fprintf (stderr, "PAM service requested binary response for truncated query");
      return NULL;
    }

  if (GDM_PAM_EXTENSION_MESSAGE_INVALID_TYPE (extended_message))
    {
      fprintf (stderr, "PAM service requested binary response for unadvertised query type");
      return NULL;
    }

  if (GDM_PAM_EXTENSION_MESSAGE_MATCH (extended_message, supported_extensions,
                                       GDM_PAM_EXTENSION_PRIVATE_STRING))
    {
      GdmPamExtensionStringProtocol *string_request =
        (GdmPamExtensionStringProtocol *) extended_message;

      *proto_name = string_request->protocol_name;
      *proto_version = string_request->version;

      return string_request->value;
    }

  return NULL;
}

static inline void
format_gdm_string_protocol_reply (const char  *proto_name,
                                  int          proto_version,
                                  const char  *reply,
                                  const char **out_pam_reply,
                                  size_t      *out_pam_reply_size)
{
  GdmPamExtensionStringProtocol *string_response =
    malloc (GDM_PAM_EXTENSION_PRIVATE_STRING_SIZE);

  GDM_PAM_EXTENSION_PRIVATE_STRING_RESPONSE_INIT (string_response,
                                                  proto_name,
                                                  proto_version);

  string_response->version = proto_version;
  string_response->value = strdup (reply);

  *out_pam_reply = GDM_PAM_EXTENSION_MESSAGE_TO_PAM_REPLY (string_response);
  *out_pam_reply_size = GDM_PAM_EXTENSION_PRIVATE_STRING_SIZE;
}
