Required Go Packages <br />
	"github.com/miekg/dns" <br />
	"github.com/sirupsen/logrus" <br />
	"golang.org/x/net/dns/dnsmessage" <br />

# DoH Proxy

## Prepare
```
export GOPATH=`pwd`
go generate proxy
sudo ./bin/proxy
```

## Modules

### client.go

This module is designed to handle client side traffic. For the most part, if you want to run a separate thread listening to client traffic, use this module and configure your client. 
For client configuration example, check out /src/proxy/proxy.go

### server.go

This module is used to send DNS requests to public servers. It supports both DNS and DoH types of requests. If you have your own client set up or you want to do modifications with the response received, use this module. 

## TODO

Currently the server is going through a new set of implementation for DNS and DoH to make it full object oriented. 
Google DoH configuration is changing regularly. Therefore handling DoH requests is also constantly updated to catch up with Google's update. 