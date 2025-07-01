package localentries

import (
	"bufio"
	"context"
	"os"
	"strconv"
	"strings"

	"github.com/ubuntu/authd/internal/users/types"
	"github.com/ubuntu/authd/log"
	"github.com/ubuntu/decorate"
)

var passwdFile = "/etc/passwd"

// ParseLocalPasswdFile reads the local passwd file and returns a slice of UserEntry structs.
func ParseLocalPasswdFile() (entries []types.UserEntry, err error) {
	defer decorate.OnError(&err, "could not parse local passwd file %s", passwdFile)

	log.Debugf(context.Background(), "Parsing local passwd file: %s", passwdFile)

	f, err := os.Open(passwdFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// The format of the local passwd file is:
	// username:password:uid:gid:gecos:home:shell
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue // Skip empty lines and comments
		}

		fields := strings.SplitN(line, ":", 7)
		if len(fields) < 7 {
			log.Warningf(context.Background(), "Skipping invalid entry in %s (invalid format): %s", passwdFile, line)
			continue
		}

		uid, err := strconv.ParseUint(fields[0], 10, 32)
		if err != nil {
			log.Warningf(context.Background(), "Skipping invalid entry in %s (invalid UID): %s", passwdFile, line)
			continue
		}

		gid, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			log.Warningf(context.Background(), "Skipping invalid entry in %s (invalid GID): %s", passwdFile, line)
		}

		entry := types.UserEntry{
			Name:  fields[0],
			UID:   uint32(uid),
			GID:   uint32(gid),
			Gecos: fields[4],
			Dir:   fields[5],
			Shell: fields[6],
		}

		entries = append(entries, entry)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}
