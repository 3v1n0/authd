Output mandatory_password_reset.txt
Output mandatory_password_reset.gif # If we don't specify a .gif output, it will create a default out.gif file.

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
Type "user-needs-reset"
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
Type "goodpass"
Enter
Sleep 100ms
Show

Hide
Type "newpass"
Sleep 100ms
Show

Hide
Tab
Type "newpass"
Sleep 100ms
Show

Hide
Enter
Sleep 100ms
Show

Sleep 100ms
