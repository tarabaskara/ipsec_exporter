package ipsec

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"

	"github.com/prometheus/common/log"
)

type status struct {
	up             bool
	status         connectionStatus
	bytesIn        int
	bytesOut       int
	packetsIn      int
	packetsOut     int
	numConnections int
	users          []user
}

type user struct {
	name   string
	userIp string
	vpnIp  string
}

type connectionStatus int

const (
	tunnelInstalled       connectionStatus = 0
	connectionEstablished connectionStatus = 1
	down                  connectionStatus = 2
	unknown               connectionStatus = 3
	ignored               connectionStatus = 4
)

type statusProvider interface {
	statusOutput(tunnel connection) (string, error)
}

type cliStatusProvider struct {
}

func (c *cliStatusProvider) statusOutput(tunnel connection) (string, error) {
	cmd := exec.Command("sudo", "ipsec", "statusall", tunnel.name)
	out, err := cmd.Output()

	if err != nil {
		return "", err
	}

	return string(out), nil
}

func queryStatus(ipSecConfiguration *Configuration, provider statusProvider) map[string]*status {
	statusMap := map[string]*status{}

	for _, connection := range ipSecConfiguration.tunnel {
		if connection.ignored {
			statusMap[connection.name] = &status{
				up:     true,
				status: ignored,
			}
			continue
		}

		if out, err := provider.statusOutput(connection); err != nil {
			log.Warnf("Unable to retrieve the status of tunnel '%s'. Reason: %v", connection.name, err)
			statusMap[connection.name] = &status{
				up:     false,
				status: unknown,
			}
		} else {
			statusMap[connection.name] = &status{
				up:             true,
				status:         extractStatus([]byte(out)),
				bytesIn:        extractIntWithRegex(out, `([[0-9]+) bytes_i`),
				bytesOut:       extractIntWithRegex(out, `([[0-9]+) bytes_o`),
				packetsIn:      extractIntWithRegex(out, `bytes_i \(([[0-9]+) pkts`),
				packetsOut:     extractIntWithRegex(out, `bytes_o \(([[0-9]+) pkts`),
				numConnections: extractNumberOfConnections(connection.name, out),
				users:          extractUsers(connection.name, out),
			}
		}
	}

	return statusMap
}

func extractUsers(connectionName, statusLine string) []user {
	r := regexp.MustCompile(fmt.Sprintf(`%s\[.+?\]: ESTABLISHED.+\n.+Remote EAP identity.+\n.+\n.+\n.+\n.+\n.+=== .+?\/`, connectionName))
	blockUsers := r.FindAllString(statusLine, -1)

	users := make([]user, len(blockUsers))

	for i, blockUser := range blockUsers {
		r = regexp.MustCompile(`(?s)ESTABLISHED.+?\.{3}(.+?)\[.+?EAP identity: (.+?)\n.+=== (.+?)\/`)
		matches := r.FindAllStringSubmatch(blockUser, -1)
		match := matches[0]
		users[i] = user{
			userIp: match[1],
			name:   match[2],
			vpnIp:  match[3],
		}
	}
	return users
}

func extractNumberOfConnections(connectionName, statusLine string) int {
	r := regexp.MustCompile(fmt.Sprintf(`%s\[.+?\]: ESTABLISHED`, connectionName))
	matches := r.FindAllString(statusLine, -1)
	return len(matches)
}

func extractStatus(statusLine []byte) connectionStatus {
	noMatchRegex := regexp.MustCompile(`no match`)
	tunnelEstablishedRegex := regexp.MustCompile(`{[0-9]+}: *INSTALLED`)
	connectionEstablishedRegex := regexp.MustCompile(`[[0-9]+]: *ESTABLISHED`)

	if connectionEstablishedRegex.Match(statusLine) {
		if tunnelEstablishedRegex.Match(statusLine) {
			return tunnelInstalled
		} else {
			return connectionEstablished
		}
	} else if noMatchRegex.Match(statusLine) {
		return down
	}

	return unknown
}

func extractIntWithRegex(input string, regex string) int {
	re := regexp.MustCompile(regex)
	match := re.FindStringSubmatch(input)
	if len(match) >= 2 {
		i, err := strconv.Atoi(match[1])
		if err != nil {
			return 0
		}
		return i
	}

	return 0
}
