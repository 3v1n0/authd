package localgroups

// #include <stdlib.h>
// #include <string.h>
// #include <errno.h>
// #include <pwd.h>
//
// void unset_errno(void) {
//   errno = 0;
// }
// int get_errno(void) {
//   return errno;
// }
import "C"
import "fmt"

// getPasswdUsernames gets the list of users using `getpwent` and returns their usernames.
func getPasswdUsernames() []string {
	C.setpwent()
	defer C.endpwent()

	var entries []string
	for {
		cPasswd := C.getpwent()
		if cPasswd == nil {
			break
		}

		entries = append(entries, C.GoString(cPasswd.pw_name))
	}

	return entries
}

// Passwd represents a passwd entry.
type Passwd struct {
	Name string
	UID  uint32
}

func GetPasswdEntries() ([]Passwd, error) {
	C.setpwent()
	defer C.endpwent()

	var entries []Passwd
	for {
		C.unset_errno()
		cPasswd := C.getpwent()
		if C.get_errno() != 0 {
			return nil, fmt.Errorf("getpwent failed: %s", C.strerror(C.get_errno()))
		}
		if cPasswd == nil {
			break
		}

		entries = append(entries, Passwd{
			Name: C.GoString(cPasswd.pw_name),
			UID:  uint32(cPasswd.pw_uid),
		})
	}

	return entries, nil
}
