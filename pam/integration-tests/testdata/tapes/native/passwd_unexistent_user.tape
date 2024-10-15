Hide
Type "${AUTHD_TEST_TAPE_COMMAND}"
Enter
Wait /Username:$/
Show

Hide
Type "user-unexistent"
Show

Hide
Enter
Wait /Select broker:/
Show

Hide
Type "2"
Enter
Wait
Show

Sleep ${AUTHD_SLEEP_DEFAULT}
