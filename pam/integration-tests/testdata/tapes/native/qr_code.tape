Hide
Type "if [ -v AUTHD_PAM_CLI_TERM ]; then export TERM=${AUTHD_PAM_CLI_TERM}; fi"
Enter
Show

Hide
Type "${AUTHD_TEST_TAPE_COMMAND}"
Enter
Wait /Select broker:/
Show

Hide
Type "2"
Enter
Wait /Gimme your password:/
Show

Hide
Type "r"
Enter
Wait+Screen /7 - Use a QR code/
Wait /Select authentication mode:/
Show

Hide
Type "7"
Enter
Wait /Select action:/
Show

Hide
Type "2"
Enter
Wait /Select action:/
Show

Hide
Type "2"
Enter
Wait /Select action:/
Show

Hide
Type "2"
Enter
Wait /Select action:/
Show

Hide
Type "2"
Enter
Wait /Select action:/
Show

Hide
Type "1"
Enter
Wait@${AUTHD_SLEEP_EXAMPLE_BROKER_QRCODE_WAIT} * 1.2
Show

Sleep ${AUTHD_SLEEP_DEFAULT}
