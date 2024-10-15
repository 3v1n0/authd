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
Wait@${AUTHD_SLEEP_EXAMPLE_BROKER_MFA_WAIT}/2 /Plug your fido device and press with your thumb/
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
Wait@${AUTHD_SLEEP_EXAMPLE_BROKER_MFA_WAIT}/2 /Plug your fido device and press with your thumb/
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
Wait /Unlock your phone \+33... or accept request on web interface/
Show

Hide
Enter
Wait@${AUTHD_SLEEP_EXAMPLE_BROKER_MFA_WAIT}*1.2 /Plug your fido device and press with your thumb/
Show

Hide
Enter
Wait@${AUTHD_SLEEP_EXAMPLE_BROKER_MFA_WAIT}*1.2
Show

Hide
Sleep ${AUTHD_SLEEP_DEFAULT}
Show

Sleep ${AUTHD_SLEEP_DEFAULT}
