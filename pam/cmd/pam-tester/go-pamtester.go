package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"syscall"

	"github.com/msteinert/pam/v2"
	"golang.org/x/term"
)

var (
	confDir  = flag.String("confdir", "", "Pam configuration directory")
	libName  = flag.String("I", "", "Item value")
	typeName = flag.String("E", "", "E value")
)

func usage() {
	toolName := filepath.Base(os.Args[0])
	fmt.Fprintf(os.Stderr, "Usage of %s:\n", toolName)
	fmt.Fprintf(os.Stderr, "\t%s [-v] [-I item=value] [-E var=value] service user operation [operation ...]\n", toolName)
	flag.PrintDefaults()
}

type newLineString struct{ string }

// Scan is used by fmt.Scan.
func (n *newLineString) Scan(state fmt.ScanState, verb rune) error {
	tok, err := state.Token(false, func(r rune) bool {
		return r != '\n'
	})
	if err != nil {
		return err
	}
	if _, _, err := state.ReadRune(); err != nil {
		if len(tok) == 0 {
			panic(err)
		}
	}
	n.string = string(tok)
	return nil
}

func mainFunc() error {
	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) < 3 {
		flag.Usage()
		os.Exit(1)
	}

	service := args[0]
	user := args[1]
	operation := args[2]
	confPath := ""
	if confDir != nil {
		confPath = *confDir
	}

	// log.Println("service", service)
	// log.Println("user", user)
	// log.Println("operation", operation)
	// log.Println("confPath", confPath)

	tx, err := pam.StartConfDir(service, user, pam.ConversationFunc(
		func(style pam.Style, msg string) (string, error) {
			switch style {
			case pam.TextInfo:
				fmt.Fprintf(os.Stderr, "PAM Info Message: %s\n", msg)

			case pam.ErrorMsg:
				fmt.Fprintf(os.Stderr, "PAM Error Message: %s\n", msg)

			case pam.PromptEchoOn:
				fmt.Print(msg)
				var input newLineString
				_, err := fmt.Scanln(&input)
				fmt.Print("\n")
				if err != nil {
					log.Fatalf("Input error: %v", err)
					return "", err
				}
				return input.string, nil

			case pam.PromptEchoOff:
				fmt.Print(msg)
				input, err := term.ReadPassword(syscall.Stdin)
				fmt.Print("\n")
				if err != nil {
					log.Fatal(err)
					return "", err
				}
				return string(input), nil
			default:
				err := fmt.Errorf("PAM style %d not implemented", style)
				fmt.Print(err)
				return "", err
			}
			return "", nil
		}), confPath)
	if err != nil {
		return fmt.Errorf("error starting transaction with service %s: %v", service, err)
	}

	// waitChan := make(chan struct{})

	defer func() {
		// <-waitChan
		err := tx.End()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed terminating pam: %v", err)
		}
	}()

	// go func() error {
	switch operation {
	case "authenticate":
		err = tx.Authenticate(pam.Flags(0))
	case "acct_mgmt":
		err = tx.AcctMgmt(pam.Flags(0))
	case "open_session":
		err = tx.OpenSession(pam.Flags(0))
	case "close_session":
		err = tx.CloseSession(pam.Flags(0))
	case "chauthtok":
		err = tx.ChangeAuthTok(pam.Flags(0))
	default:
		// waitChan <- struct{}{}
		return fmt.Errorf("unknown operation %s", operation)
	}

	if err != nil {
		// waitChan <- struct{}{}
		return fmt.Errorf("%s: %v", operation, err)
	}
	// waitChan <- struct{}{}
	// return nil
	// }()

	// time.Sleep(time.Millisecond * 200)

	fmt.Println("Now let's do acctmgmt... Just to try")
	ret := tx.AcctMgmt(0)
	fmt.Println("Act mgmt finished", ret)
	fmt.Println("fooo")
	fmt.Println("fooo")
	fmt.Println("fooo")
	fmt.Println("fooo")
	return ret
}

func main() {
	if err := mainFunc(); err != nil {
		log.Fatal(err)
	}
}
