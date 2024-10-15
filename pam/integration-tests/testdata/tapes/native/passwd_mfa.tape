Hide
Type "${AUTHD_TEST_TAPE_COMMAND}"
Enter
Wait /Username:$/
Show

Hide
Type "user-mfa"
Enter
Wait /Select broker:/
Show

Hide
Type "2"
Enter
Wait /Gimme your password:/
Show

Hide
Type "r"
Enter
Wait /Select authentication mode:/
Wait+Screen /1 - Password authentication/
Show

Hide
Type "1"
Enter
Wait /Gimme your password:/
Show

Hide
Type "goodpass"
Enter
Wait /Plug your fido device and press with your thumb:/
Show

Hide
Type "r"
Enter
Wait /Select authentication mode:/
Wait+Screen /1 - Use your fido device foo/
Show

Hide
Type "1"
Enter
Wait /Plug your fido device and press with your thumb:/
Show

Hide
Enter
Wait@${AUTHD_SLEEP_EXAMPLE_BROKER_MFA_WAIT}*1.2 /Unlock your phone \+33... or accept request on web interface:/
Show

Hide
Type "r"
Enter
Wait /Select authentication mode:/
Wait+Screen /1 - Use your phone \+33\.\.\./
Show

Hide
Type "1"
Enter
Wait /Unlock your phone \+33\.\.\. or accept request on web interface:/
Show

Hide
Enter
Wait@${AUTHD_SLEEP_EXAMPLE_BROKER_MFA_WAIT}*1.2 /Enter your new password:/
Show

Hide
Type "authd2404"
Enter
Wait /Enter your new password:/
Show

Hide
Type "authd2404"
Enter
Wait
Show

Sleep ${AUTHD_SLEEP_DEFAULT}
