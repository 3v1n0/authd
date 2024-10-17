Hide
Type "${AUTHD_TEST_TAPE_COMMAND}"
Enter
Wait /Username:$/
Show

Hide
Type "user-integration-invalid-new-password"
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
Type "noble2404"
Enter
Wait /Enter your new password:/
Show

Hide
Type "noble2404"
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

Hide
Type "clear"
Enter
Wait
Show

# Repeat again, to check that we can use still use another new password

Hide
Type "${AUTHD_TEST_TAPE_COMMAND}"
Enter
Wait /Username:$/
Show

Hide
Type "user-integration-invalid-new-password"
Enter
Wait /Gimme your password:/
Show

Hide
Type "authd2404"
Enter
Wait /Enter your new password:/
Show

Hide
Type "noble2404"
Enter
Wait /Enter your new password:/
Show

Hide
Type "noble2404"
Enter
Wait /Enter your new password:/
Show

Hide
Type "noble2404.1"
Enter
Wait /Enter your new password:/
Show

Hide
Type "noble2404.2"
Enter
Wait /Enter your new password:/
Show

Hide
Type "goodpass"
Enter
Wait /Enter your new password:/
Show

Hide
Type "goodpass"
Enter
Wait
Show

Sleep ${AUTHD_SLEEP_DEFAULT}
