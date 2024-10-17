Hide
Type "${AUTHD_TEST_TAPE_COMMAND}"
Enter
Wait /Username: user name$/
Sleep ${AUTHD_SLEEP_DEFAULT}
Show

Hide
Type "user-mfa-with-reset"
Wait /Username: user-mfa-with-reset$/
Show

Hide
Enter
Wait+Screen /Select your provider/
Wait+Screen /2. ExampleBroker/
Show

Hide
Type "2"
Wait+Screen /Gimme your password/
Wait
Show

Hide
Sleep ${AUTHD_SLEEP_DEFAULT}
Type "goodpass"
Show

Hide
Enter
Wait@${AUTHD_SLEEP_EXAMPLE_BROKER_MFA_WAIT}/2 /Plug your fido device and press with your thumb/
Show

# Wait for MFA auth to happen
Hide
Wait+Screen@${AUTHD_SLEEP_EXAMPLE_BROKER_MFA_WAIT} * 1.2 /Enter your new password \(3 days until mandatory\)/
Wait+Screen@${AUTHD_SLEEP_EXAMPLE_BROKER_MFA_WAIT} * 1.2 /New password:\n>\n/
Show

Hide
Sleep ${AUTHD_SLEEP_DEFAULT}
Type "goodpass"
Show

Hide
Enter
Wait+Screen /New password:\n>\n/
Show

Hide
Sleep ${AUTHD_SLEEP_DEFAULT}
Type "password"
Show

Hide
Enter
Wait+Screen /New password:\n>\n/
Show

Hide
Sleep ${AUTHD_SLEEP_DEFAULT}
Type "goodpass"
Show

Hide
Enter
Wait+Screen /New password:\n>\n/
Show

Hide
Sleep ${AUTHD_SLEEP_DEFAULT}
Type "1234"
Show

Hide
Enter
Wait+Screen /New password:\n>\n/
Show

Hide
Sleep ${AUTHD_SLEEP_DEFAULT}
Type "authd2404"
Show

Hide
Enter
Wait+Screen /Confirm password:\n>\n/
Show

Hide
Sleep ${AUTHD_SLEEP_DEFAULT}
Type "authd2404"
Show

Hide
Enter
Wait+Screen /\nPAM Authenticate\(\)/
Wait+Screen /\nPAM AcctMgmt\(\)/
Wait
Show

Sleep ${AUTHD_SLEEP_DEFAULT}
