package main

//go:generate go get -u github.com/miekg/dns
//go:generate go get -u github.com/sirupsen/logrus
//go:generate go get -u github.com/alexthemonk/DoH_Proxy
//go:generate go build -o $GOPATH/bin/proxy proxy
