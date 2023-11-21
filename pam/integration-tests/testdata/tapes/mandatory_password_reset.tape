Output mandatory_password_reset.txt
Output mandatory_password_reset.gif
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
Type "-needs-reset"
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
