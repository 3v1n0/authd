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
Show

Hide
Type "r"
Enter
Wait /Select broker:/
Show

Hide
Type "invalid-ID"
Enter
Wait /Select broker:/
Show

Hide
Type "555"
Enter
Wait /Select broker:/
Show

Hide
Type "1"
Enter
Wait
Show

Sleep ${AUTHD_SLEEP_DEFAULT}
