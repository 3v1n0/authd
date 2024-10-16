Hide
Type "${AUTHD_TEST_TAPE_COMMAND}"
Enter
Wait /Username: user name$/
Show

Hide
Type "user-local-broker"
Wait+Screen /Username: user-local-broker\n/
Show

Hide
Enter
Wait+Screen /Select your provider/
Wait+Screen /1. local/
Show

Hide
Enter
Wait+Screen /\nPAM Authenticate\(\)/
Wait+Screen /\nPAM AcctMgmt\(\)/
Wait
Show

Sleep ${AUTHD_SLEEP_DEFAULT}
