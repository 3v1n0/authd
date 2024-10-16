Hide
Type "${AUTHD_TEST_TAPE_COMMAND}"
Enter
Wait /Username: user name$/
Show

Hide
Type "user-unexistent"
Wait+Screen /Username: user-unexistent\n/
Show

Hide
Enter
Wait+Screen /Select your provider/
Wait+Screen /2. ExampleBroker/
Show

Hide
Type "2"
Wait+Screen /\nPAM Authenticate\(\)/
Wait+Screen /\nPAM AcctMgmt\(\)/
Wait
Show

Sleep ${AUTHD_SLEEP_DEFAULT}
