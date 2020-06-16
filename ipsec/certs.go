package ipsec

import (
	"os"
	"os/exec"
	"regexp"
	"time"

	"github.com/prometheus/common/log"
)

type certsProvider interface {
	certsOutput() (string, error)
}

type certs struct {
	name         string
	notAfterTime time.Time
	serial       string
}

type cliCertsProvider struct {
}

func (c *cliCertsProvider) certsOutput() (string, error) {
	cmd := exec.Command("ipsec", "listcerts")
	if os.Geteuid() != 0 {
		cmd = exec.Command("sudo", "ipsec", "listcerts")
	}
	out, err := cmd.Output()

	if err != nil {
		return "", err
	}

	return string(out), nil
}

func queryCerts(outputProvider certsProvider) []certs {
	out, err := outputProvider.certsOutput()

	if err != nil {
		log.Warnf("Unable to retrieve the certs. Reason: %v", err)
		return nil
	}

	r := regexp.MustCompile(`(?sm)altNames:\s+(.+?)$.+?serial:\s+(.+?)$.+?not after\s+(.+?),`)
	matches := r.FindAllStringSubmatch(out, -1)

	listCerts := make([]certs, len(matches))
	for i, match := range matches {
		layout := "Jan 02 15:04:05 2006"
		t, _ := time.Parse(layout, match[3])
		listCerts[i] = certs{
			name:         match[1],
			serial:       match[2],
			notAfterTime: t,
		}
	}

	return listCerts
}
