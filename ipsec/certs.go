package ipsec

import (
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
	cmd := exec.Command("sudo", "ipsec", "listcerts")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return string(out), nil
}

func queryCerts(outputProvider certsProvider) []certs {
	listCerts := []certs{}

	out, err := outputProvider.certsOutput()

	if err != nil {
		log.Warnf("Unable to retrieve the certs. Reason: %v", err)
		return nil
	}

	r := regexp.MustCompile(`(?s)(subject.+?authkey)`)
	matches := r.FindAllStringSubmatch(out, -1)

	for _, rawCert := range matches {
		c := parseCert(rawCert[0])
		if c != nil {
			listCerts = append(listCerts, *c)
		}
	}

	return listCerts
}

func parseCert(rawCert string) *certs {
	var result certs

	rSubject := regexp.MustCompile(`subject:\s*.*?CN=(.+?)[;"]`)
	matchSubject := rSubject.FindAllStringSubmatch(rawCert, 1)
	if len(matchSubject) == 0 {
		log.Warn("Failed to parse certificate subject")
		return nil
	}

	rExpiry := regexp.MustCompile(`not after\s+(.+?),`)
	matchExpiry := rExpiry.FindAllStringSubmatch(rawCert, 1)
	if len(matchExpiry) == 0 {
		log.Warn("Failed to parse certificate expiry")
		return nil
	}
	layout := "Jan 02 15:04:05 2006"
	t, _ := time.Parse(layout, matchExpiry[0][1])

	rSerial := regexp.MustCompile(`serial:\s+(.+)`)
	matchSerial := rSerial.FindAllStringSubmatch(rawCert, 1)
	if len(matchSerial) == 0 {
		log.Warn("Failed to parse certificate serial")
		return nil
	}

	result.name = matchSubject[0][1]
	result.serial = matchSerial[0][1]
	result.notAfterTime = t

	return &result
}
