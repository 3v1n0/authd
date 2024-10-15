Hide
Type "${AUTHD_TEST_TAPE_COMMAND}"
Enter
Wait /Username:$/
Show

Hide
Type "user-integration-switch-username"
Show

Hide
Enter
Wait /Select broker:/
Show

Hide
Type "r"
Enter
Wait /Username:$/
Show

Hide
Type "user-integration-username-switched"
Show

Hide
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
Wait
Show

Sleep ${AUTHD_SLEEP_DEFAULT}
