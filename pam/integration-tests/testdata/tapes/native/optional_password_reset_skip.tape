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
Type "goodpass"
Enter
Wait /Select action:/
Show

Hide
Type "2"
Enter
Wait
Show

Sleep ${AUTHD_SLEEP_DEFAULT}
