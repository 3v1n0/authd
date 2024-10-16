Hide
Type "${AUTHD_TEST_TAPE_COMMAND}"
Enter
Wait /Username: user name$/
Sleep ${AUTHD_SLEEP_DEFAULT}
Show

Hide
Escape
Type "user-integration-switch-username"
Wait+Screen /Username: user-integration-switch-username\n/
Show

Hide
Enter
Wait+Screen /Select your provider/
Show

Hide
Escape
Wait /Username: user-integration-switch-username$/
Backspace 15
Wait+Screen /Username: user-integration-\n/
Type "username-switched"
Show

Hide
Enter
Wait+Screen /Select your provider/
Wait+Screen /2. ExampleBroker/
Show

Hide
Type "2"
Wait+Screen /Gimme your password/
Show

Hide
Type "goodpass"
Enter
Wait+Screen /\nPAM Authenticate\(\)/
Wait+Screen /\nPAM AcctMgmt\(\)/
Wait
Show

Sleep ${AUTHD_SLEEP_DEFAULT}
