Hide
Type "${AUTHD_TEST_TAPE_COMMAND}"
Enter
Wait /Username: user name$/
Sleep ${AUTHD_SLEEP_DEFAULT}
Show

Hide
Type "user-integration-max-attempts"
Wait /Username: user-integration-max-attempts$/
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
Type "wrongpass"
Enter
Wait /invalid password/
Wait+Screen /Gimme your password\n>\n/
Show

Hide
Sleep ${AUTHD_SLEEP_DEFAULT}
Type "wrongpass"
Enter
Wait /invalid password/
Wait+Screen /Gimme your password\n>\n/
Show

Hide
Sleep ${AUTHD_SLEEP_DEFAULT}
Type "wrongpass"
Enter
Wait /invalid password/
Wait+Screen /Gimme your password\n>\n/
Show

Hide
Sleep ${AUTHD_SLEEP_DEFAULT}
Type "wrongpass"
Enter
Wait /invalid password/
Wait+Screen /Gimme your password\n>\n/
Show

Hide
Sleep ${AUTHD_SLEEP_DEFAULT}
Type "wrongpass"
Enter
Wait+Screen /invalid password/
Wait+Screen /\nPAM Authenticate\(\)/
Wait+Screen /\nPAM AcctMgmt\(\)/
Wait
Show

Sleep ${AUTHD_SLEEP_DEFAULT}
