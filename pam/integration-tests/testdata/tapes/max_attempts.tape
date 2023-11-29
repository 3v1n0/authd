Output max_attempts.txt
Output max_attempts.gif # If we don't specify a .gif output, it will create a default out.gif file.

# Configuration header to standardize the output.
# Does not work with the "Source" command.
Set Width 1800
Set Height 800
Set FontFamily "Ubuntu Mono"
Set FontSize 20
Set Padding 0
Set Margin 0
Set Shell bash

Hide
Type "./pam_authd socket=/tmp/authd.sock"
Enter
Sleep 100ms
Show

Hide
Escape
Backspace
Type "-max-attempts"
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
Type "wrongpass"
Enter
Sleep 100ms
Show

Hide
Type "wrongpass"
Enter
Sleep 100ms
Show

Hide
Type "wrongpass"
Enter
Sleep 100ms
Show

Hide
Type "wrongpass"
Enter
Sleep 100ms
Show

Hide
Type "wrongpass"
Enter
Sleep 100ms
Show

Sleep 100ms
