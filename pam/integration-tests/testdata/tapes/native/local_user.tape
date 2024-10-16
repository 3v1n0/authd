Hide
Type "${AUTHD_TEST_TAPE_COMMAND}"
Enter
Wait /Username:$/
Show

Hide
Type "root"
Enter
Wait+Screen /\nPAM Authenticate\(\)/
Wait+Screen /\nPAM AcctMgmt\(\)/
Wait
Show

Sleep ${AUTHD_SLEEP_DEFAULT}
