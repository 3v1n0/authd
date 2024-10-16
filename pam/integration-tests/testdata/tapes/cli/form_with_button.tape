Hide
Type "${AUTHD_TEST_TAPE_COMMAND}"
Enter
Wait /Username: user name$/
Show

Hide
Type "user-integration-form-w-button"
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
Escape
Wait+Screen /Select your authentication method/
Wait+Screen /7\. Authentication code/
Show

Hide
Type "7"
Wait+Screen /Enter your one time credential\n>\n/
Wait /[ Resend sms ]/
Show

Hide
Tab
Show

Hide
Enter
Wait+Screen /Enter your one time credential\n>\n/
Wait /[ Resend sms ]/
Show

Hide
Type "temporary pass00"
Enter
Wait+Screen /\nPAM Authenticate\(\)/
Wait+Screen /\nPAM AcctMgmt\(\)/
Wait
Show

Sleep ${AUTHD_SLEEP_DEFAULT}
