Output remember_broker_and_mode.txt
Output remember_broker_and_mode.gif

# Configuration header to standardize the output.
# Does not work with the "Source" command.
Set Width 1200
Set Height 600
Set FontFamily "Ubuntu Mono"
Set FontSize 20
Set Padding 0
Set Margin 0
Set Shell bash

Hide
Type "./pam_authd socket=/tmp/pam-cli-tests.sock"
Enter
Sleep 100ms
Show

Hide
Escape
Backspace
Type "user-integration-remember-mode"
Sleep 100ms
Show

Hide
Enter
Sleep 100ms
Show

Hide
Type "2"
Sleep 100ms
Escape
Sleep 100ms
Show

Hide
Type "7"
Sleep 100ms
Show

Hide
Type "temporary pass0"
Enter
Sleep 100ms
Show

Hide
Type "./pam_authd socket=/tmp/pam-cli-tests.sock"
Enter
Sleep 100ms
Show

Hide
Escape
Backspace
Type "user-integration-remember-mode"
Sleep 100ms
Show

Hide
Enter
Sleep 100ms
Show

Hide
Type "temporary pass0"
Enter
Sleep 100ms
Show

Sleep 100ms
