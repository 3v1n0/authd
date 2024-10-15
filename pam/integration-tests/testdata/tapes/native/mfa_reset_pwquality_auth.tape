Hide
Type "${AUTHD_TEST_TAPE_COMMAND}"
Enter
Wait /Select broker:/
Show

Hide
Type "2"
Show

Hide
Enter
Wait /Gimme your password:/
Show

Hide
Type "goodpass"
Enter
Wait /Plug your fido device and press with your thumb:/
Show

# Wait for MFA auth to happen
Hide
Enter
Wait /Select action:/
Show

Hide
Type "1"
Enter
Wait@${AUTHD_SLEEP_EXAMPLE_BROKER_MFA_WAIT}*1.2 /Enter your new password \(3 days until mandatory\):/
Show

Hide
Type "goodpass"
Enter
Wait /Enter your new password \(3 days until mandatory\):/
Show

Hide
Type "password"
Enter
Wait /Enter your new password \(3 days until mandatory\):/
Show

Hide
Type "goodpass"
Enter
Wait /Enter your new password \(3 days until mandatory\):/
Show

Hide
Type "1234"
Enter
Wait /Enter your new password \(3 days until mandatory\):/
Show

Hide
Type "authd2404"
Enter
Wait /Enter your new password \(3 days until mandatory\):/
Show

Hide
Type "authd2404"
Enter
Wait
Show

Sleep ${AUTHD_SLEEP_DEFAULT}
