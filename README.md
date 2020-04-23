Required Go Packages
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/dns/dnsmessage"

# DoH Proxy

## Prepare
```
export GOPATH=`pwd`
go generate proxy
sudo ./bin/proxy
```
