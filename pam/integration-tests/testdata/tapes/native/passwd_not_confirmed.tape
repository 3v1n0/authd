Hide
Type "${AUTHD_TEST_TAPE_COMMAND}"
Enter
Wait /Username:$/
Show

Hide
Type "user-integration-wrong-confirmation"
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
Wait /Enter your new password:/
Show

Hide
Type "authd2404"
Enter
Wait /Enter your new password:/
Show

Hide
Type "badpass"
Enter
Wait /Enter your new password:/
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
