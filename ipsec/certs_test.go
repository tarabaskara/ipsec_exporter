package ipsec

import "testing"

type dummyCertsProvider struct {
	returnString string
	returnError  error
}

func (d *dummyCertsProvider) certsOutput() (string, error) {
	if d.returnError != nil {
		return "", d.returnError
	}
	return d.returnString, nil
}

func TestQueryCerts(t *testing.T) {
	certs := queryCerts(&dummyCertsProvider{returnString: `
List of X.509 End Entity Certificates:

  altNames:  org1.vpn.something.com,org2.vpn.something.com,
  subject:  "CN=org1.vpn.something.com"
  issuer:   "C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3"
  serial:    04:0f:8e:47:cc:17:38:c4:54:15:1a:24:28:0c:e7:05:3e:f5
  validity:  not before Feb 04 11:01:58 2020, ok
             not after  May 04 11:01:58 2020, ok
  pubkey:    RSA 4096 bits, has private key
  keyid:     7d:2e:16:2b:0e:71:c6:19:3b:a2:36:32:d8:86:2a:5e:39:8e:ca:76
  subjkey:   d1:54:0a:08:3e:2f:99:8e:54:9e:1f:d0:ec:91:11:c0:04:ff:d7:b1
  authkey:   a8:4a:6a:63:04:7d:dd:ba:e6:d1:14:b7:a6:45:65:ef:f3:a8:ec:a1

  altNames:  org2.vpn.something.com
  subject:  "CN=org2.vpn.something.com"
  issuer:   "C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3"
  serial:    03:65:89:ef:d3:e6:90:a2:d1:3d:c2:ef:02:b2:88:c4:49:28
  validity:  not before Feb 07 11:01:11 2020, ok
             not after  May 07 11:01:11 2020, ok
  pubkey:    RSA 4096 bits
  keyid:     65:f0:fc:61:99:b8:6e:ba:0b:ec:ba:e5:42:b5:e8:9f:ae:b2:86:d5
  subjkey:   69:c0:59:38:d7:11:6f:b5:86:92:da:1c:9d:c7:2a:a3:89:5b:0b:a1
  authkey:   a8:4a:6a:63:04:7d:dd:ba:e6:d1:39:b7:c8:45:65:ef:f3:a8:ec:a1
`})

	expectedTotalCerts := 2
	if expectedTotalCerts != len(certs) {
		t.Errorf("Expected total number of certs'%d' got '%d", expectedTotalCerts, len(certs))
		return
	}

	expectedNames := []string{"org1.vpn.something.com", "org2.vpn.something.com"}
	for i, name := range expectedNames {
		if name != certs[i].name {
			t.Errorf("Expected certs vpn name '%s' got '%s", name, certs[i].name)
			return
		}
	}

	expectedSerials := []string{"04:0f:8e:47:cc:17:38:c4:54:15:1a:24:28:0c:e7:05:3e:f5", "03:65:89:ef:d3:e6:90:a2:d1:3d:c2:ef:02:b2:88:c4:49:28"}
	for i, serial := range expectedSerials {
		if serial != certs[i].serial {
			t.Errorf("Expected certs vpn serial '%s' got '%s", serial, certs[i].serial)
			return
		}
	}

	expectedNotAfter := []int{1588590118, 1588849271}
	for i, notAfterTime := range expectedNotAfter {
		if notAfterTime != int(certs[i].notAfterTime.Unix()) {
			t.Errorf("Expected certs vpn not after '%d' got '%d", notAfterTime, int(certs[i].notAfterTime.Unix()))
			return
		}
	}
}
