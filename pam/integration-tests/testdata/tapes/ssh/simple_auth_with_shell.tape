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
Type "goodpass"
Enter
Wait /^\$/
Show

Hide
Type "echo $USER"
Enter
Show

Hide
Type '[ -n "${SSH_CONNECTION}" ] && echo "Inside SSH"'
Enter
Show

Hide
Ctrl+D
Wait
Show

Hide
Type "echo ${SSH_CONNECTION:-Outside SSH}"
Enter
Wait
Show

Sleep ${AUTHD_SLEEP_DEFAULT}
