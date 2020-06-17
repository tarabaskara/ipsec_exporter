#!/bin/bash
VERSION=$1

GOOS=linux GOARCH=amd64 go build .
rm -rf "ipsec_exporter-$VERSION.linux-amd64.tar.gz"
tar czfv "ipsec_exporter-$VERSION.linux-amd64.tar.gz" "ipsec_exporter"
sha256sum "ipsec_exporter-$VERSION.linux-amd64.tar.gz" | tee sha256sums.txt