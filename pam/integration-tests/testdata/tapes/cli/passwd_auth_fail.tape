Hide
TypeInPrompt+Shell "${AUTHD_TEST_TAPE_COMMAND}"
Enter
Wait /Username: user name\n/
Show

Hide
TypeUsername "${AUTHD_TEST_TAPE_USERNAME}"
Show

Hide
Enter
Wait+Screen /Select your provider/
Wait+Screen /2. ExampleBroker/
Show

Hide
Type "2"
Wait+CLIPrompt /Gimme your password/ /Press escape key to go back to select the authentication method/
Show

Hide
TypeCLIPassword "wrongpass"
Show

Hide
Enter
Wait+CLIPrompt /Gimme your password/ /invalid password '.+', should be[^\n]+[\n]+[ ]*Press escape key to go back to select the authentication method/
Show

Hide
TypeCLIPassword "wrongpass"
Show

Hide
Enter
Wait+CLIPrompt /Gimme your password/ /invalid password '.+', should be[^\n]+[\n]+[ ]*Press escape key to go back to select the authentication method/
Show

Hide
TypeCLIPassword "wrongpass"
Show

Hide
Enter
Wait+CLIPrompt /Gimme your password/ /invalid password '.+', should be[^\n]+[\n]+[ ]*Press escape key to go back to select the authentication method/
Show

Hide
TypeCLIPassword "wrongpass"
Show

Hide
Enter
Wait+CLIPrompt /Gimme your password/ /invalid password '.+', should be[^\n]+[\n]+[ ]*Press escape key to go back to select the authentication method/
Show

Hide
TypeCLIPassword "wrongpass"
Show

Hide
Enter
Wait+Screen /invalid password '.+', should be[^\n]+/
${AUTHD_TEST_TAPE_COMMAND_PASSWD_FINAL_WAIT}
Show
