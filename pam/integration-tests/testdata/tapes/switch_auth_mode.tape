Output switch_auth_mode.txt
Output switch_auth_mode.gif # If we don't specify a .gif output, it will create a default out.gif file.

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
Type "user-integration-switch-mode"
Sleep 100ms
Show

Hide
Enter
Sleep 100ms
Show

Hide
Type "2"
Sleep 100ms
Show

Hide
Escape
Sleep 100ms
Show

Hide
Type "2"
Sleep 100ms
Show

Hide
Escape
Sleep 100ms
Show

Hide
Type "3"
Sleep 100ms
Show

Hide
Escape
Sleep 100ms
Show

Hide
Type "1"
Sleep 100ms
Show

Hide
Type "goodpass"
Enter
Sleep 100ms
Show

Sleep 100ms
