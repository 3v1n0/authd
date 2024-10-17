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
Wait+Screen /8 - Authentication code/
Show

Hide
Type "8"
Enter
Wait /Select action:/
Show

Hide
Type "1"
Enter
Wait /Enter your one time credential:/
Show

Hide
Type "temporary pass0"
Enter
Wait
Show

Hide
Type "clear"
Enter
Wait
Show

Hide
Type "${AUTHD_TEST_TAPE_COMMAND}"
Enter
Wait /Select action:/
Show

Hide
Type "1"
Enter
Wait /Enter your one time credential:/
Show

Hide
Type "temporary pass0"
Enter
Wait
Show

Sleep ${AUTHD_SLEEP_DEFAULT}
