#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <security/pam_modules.h>

#include "gdm-extensions/gdm-pam-extensions-common.h"

char *argv_string_get (const char **argv,
                       unsigned     i);

char *get_user (pam_handle_t *pamh);

char *set_user (pam_handle_t *pamh,
                char         *username);

const char * prompt_for_username (pam_handle_t *pamh,
                                  const char   *prompt);

const char *get_module_name (pam_handle_t *pamh);

struct pam_response *send_msg (pam_handle_t *pamh,
                               const char   *msg,
                               int           style);

static inline bool
is_gdm_extension_supported (const char *extension)
{
  return GDM_PAM_EXTENSION_SUPPORTED (extension);
}

char *gdm_private_string_protocol_send (pam_handle_t *pamh,
                                        const char   *proto_name,
                                        int           proto_version,
                                        const char   *value,
                                        char        **error);

// struct pam_response *
