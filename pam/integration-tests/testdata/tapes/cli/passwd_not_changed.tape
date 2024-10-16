Hide
Type "${AUTHD_TEST_TAPE_COMMAND}"
Enter
Wait /Username: user name$/
Show

Hide
Type "user-integration-same-new-password"
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
Type "goodpass"
Enter
Wait+Screen /New password:/
Wait
Show

Hide
Type "goodpass"
Show

Hide
Enter
Wait+Screen /New password:\n>\n/
Show

Hide
Type "authd2404"
Show

Hide
Enter
Wait+Screen /Confirm password:/
Wait
Type "authd2404"
Show

Hide
Enter
Wait+Screen /\nPAM ChangeAuthTok\(\)/
Wait+Screen /\nPAM AcctMgmt\(\)/
Wait
Show

Sleep ${AUTHD_SLEEP_DEFAULT}
