Hide
Type "${AUTHD_TEST_TAPE_COMMAND}"
Enter
Wait /Username:$/
Show

Hide
Type "user-integration-sigint"
Enter
Wait /Select broker:/
Show

Hide
Type "2"
Enter
Wait /Gimme your password:/
Show

Hide
Ctrl+C
Wait
Show

Sleep ${AUTHD_SLEEP_DEFAULT}
