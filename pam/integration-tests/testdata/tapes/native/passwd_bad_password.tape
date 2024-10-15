Hide
Type "${AUTHD_TEST_TAPE_COMMAND}"
Enter
Wait /Username:$/
Show

Hide
Type "user-integration-bad-password"
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
Enter
Wait /Enter your new password:/
Show

Hide
Type "1234"
Enter
Wait /Enter your new password:/
Show

Hide
Type "12345678"
Enter
Wait /Enter your new password:/
Show

Hide
Type "authd2404"
Enter
Wait /Enter your new password:/
Show

Hide
Type "123456789"
Enter
Wait /Enter your new password:/
Show

Hide
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
