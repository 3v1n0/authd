Hide
Type "${AUTHD_TEST_TAPE_COMMAND}"
Enter
Wait /Username: user name$/
Show

Hide
Type "user-can-reset"
Wait+Screen /Username: user-can-reset\n/
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
Wait+Screen /New password:\n>\n/
Wait /\[ Skip \]/
Show

Hide
Tab
Show

Hide
Enter
Wait+Screen /\nPAM Authenticate\(\)/
Wait+Screen /\nPAM AcctMgmt\(\)/
Wait
Show

Sleep ${AUTHD_SLEEP_DEFAULT}
