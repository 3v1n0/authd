# Configuration header to standardize the output.
# Does not work with the "Source" command.
Set Width 800
# We need an higher terminal view, as vhs doesn't scroll:
#  https://github.com/charmbracelet/vhs/issues/404
Set Height 550
# TODO: Ideally, we should use Ubuntu Mono. However, the github runner is still on Jammy, which does not have it.
# We should update this to use Ubuntu Mono once the runner is updated.
Set FontFamily "Monospace"
Set FontSize 13
Set Padding 0
Set Margin 0
Set Shell bash

Hide
Type "./pam_authd login socket=${AUTHD_TESTS_CLI_AUTHENTICATE_TESTS_SOCK} force_native_client=true"
Enter
Sleep ${AUTHD_SLEEP_DEFAULT}
Show

Hide
Type "user-needs-reset"
Sleep ${AUTHD_SLEEP_DEFAULT}
Show

Hide
Enter
Sleep ${AUTHD_SLEEP_DEFAULT}
Show

Hide
Type "2"
Enter
Sleep ${AUTHD_SLEEP_DEFAULT}
Show

Hide
Type "goodpass"
Enter
Sleep ${AUTHD_SLEEP_LONG} * 2
Show

Hide
Sleep ${AUTHD_SLEEP_DEFAULT}
Enter
Show

Hide
Type "1234"
Sleep ${AUTHD_SLEEP_DEFAULT}
Enter
Show

Hide
Type "12345678"
Sleep ${AUTHD_SLEEP_DEFAULT}
Enter
Show

Hide
Type "authd2404"
Sleep ${AUTHD_SLEEP_DEFAULT}
Enter
Show

Hide
Type "123456789"
Sleep ${AUTHD_SLEEP_DEFAULT}
Enter
Show

Hide
Enter
Sleep ${AUTHD_SLEEP_LONG} * 2
Show

Hide
Type "authd2404"
Sleep ${AUTHD_SLEEP_DEFAULT}
Enter
Show

Hide
Type "authd2404"
Enter
Sleep ${AUTHD_SLEEP_LONG} * 2
Show

Sleep ${AUTHD_SLEEP_DEFAULT}
