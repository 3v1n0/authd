Hide
Type "${AUTHD_TEST_TAPE_COMMAND}"
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
Wait+Screen /2 - Send URL to /
Show

Hide
Type "2"
Enter
Wait /enter the code:/
Show

Hide
Type "r"
Enter
Wait /Select authentication mode:/
Wait+Screen /3 - Use your fido device foo/
Show

Hide
Type "3"
Enter
Wait@${AUTHD_SLEEP_EXAMPLE_BROKER_MFA_WAIT}/2 /Plug your fido device and press with your thumb:/
Show

Hide
Type "r"
Enter
Wait /Select authentication mode:/
Wait+Screen /4 - Use your phone \+33\.\.\./
Show

Hide
Type "4"
Enter
Wait@${AUTHD_SLEEP_EXAMPLE_BROKER_MFA_WAIT}/2 /Unlock your phone \+33... or accept request on web interface:/
Show

Hide
Type "r"
Enter
Wait /Select authentication mode:/
Wait+Screen /5 - Use your phone \+1\.\.\./
Show

Hide
Type "5"
Enter
Wait@${AUTHD_SLEEP_EXAMPLE_BROKER_MFA_WAIT}/2 /Unlock your phone \+1... or accept request on web interface:/
Show

Hide
Type "r"
Enter
Wait /Select authentication mode:/
Wait+Screen /6 - Pin code/
Show

Hide
Type "6"
Enter
Wait /Enter your pin code:/
Show

Hide
Type "r"
Enter
Wait /Select authentication mode:/
Wait+Screen /7 - Use a QR code/
Show

Hide
Type "7"
Enter
Wait /Select action:/
Show

Hide
Type "r"
Enter
Wait /Select authentication mode:/
Wait+Screen /8 - Authentication code/
Show

Hide
Type "8"
Enter
Wait /Select action:/
Show

Hide
Type "r"
Enter
Wait /Select authentication mode:/
Show

Hide
Type "invalid-selection"
Enter
Wait /Select authentication mode:/
Show

Hide
Type "-1"
Enter
Wait /Select authentication mode:/
Wait+Screen /6 - Pin code/
Show

Hide
Type "6"
Enter
Wait /Enter your pin code:/
Show

Hide
Type "4242"
Enter
Wait
Show

Sleep ${AUTHD_SLEEP_DEFAULT}
