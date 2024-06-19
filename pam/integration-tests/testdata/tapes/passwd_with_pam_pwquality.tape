Output passwd_with_pam_pwquality.txt
Output passwd_with_pam_pwquality.gif # If we don't specify a .gif output, it will create a default out.gif file.

# Configuration header to standardize the output.
# Does not work with the "Source" command.
Set Width 800
Set Height 500
# TODO: Ideally, we should use Ubuntu Mono. However, the github runner is still on Jammy, which does not have it.
# We should update this to use Ubuntu Mono once the runner is updated.
Set FontFamily "Monospace"
Set FontSize 13
Set Padding 0
Set Margin 0
Set Shell bash

Hide
Type "env AUTHD_PAM_CLI_SUPPORTS_CONVERSATION=1 ./pam_authd passwd socket=${AUTHD_TESTS_CLI_AUTHTOK_TESTS_SOCK}"
Enter
Sleep 300ms
Show

Hide
Type "user-integration-pwquality"
Enter
Sleep 300ms
Show

Hide
Type "pw"
Enter
Sleep 300ms
Show

Hide
Type "newpass"
Enter
Sleep 300ms
Show

Hide
Type "newpass"
Enter
Sleep 300ms
Show

Hide
Type "2"
Sleep 300ms
Show

Hide
Type "goodpass"
Enter
Sleep 2s
Show

Hide
Type "env AUTHD_PAM_CLI_USER=user-integration-pwquality ./pam_authd login socket=${AUTHD_TESTS_CLI_AUTHTOK_TESTS_SOCK}"
Enter
Sleep 500ms
Show

Hide
Type "newpass"
Enter
Sleep 2s
Show

Sleep 300ms
