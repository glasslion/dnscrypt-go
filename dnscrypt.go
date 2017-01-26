package dnscrypt

import (
	"fmt"
	"github.com/miekg/dns"
	"net"
	"strconv"
	"strings"
	"errors"
)


type Resolver struct {
	IP string
	Port int
	PublicName string
}

type Client struct {
	Res *Resolver``
	certs []string
}

func (c *Client) retrieveCertificates() error {
	dc := new(dns.Client)
	// According to the DNSCrypt protocol, the resolver is not requires to serve certificates in both UDP and TCP.
	// It's the client's duty to try UDP first and retry TCP if UDP fails.
	var (
		err error
		r *dns.Msg
	)
	for _, protocol := range [2]string{"", "tcp"} {
		// empty protocol string represents udp
		dc.Net = protocol
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(c.Res.PublicName), dns.TypeTXT)
		r, _, err = dc.Exchange(m, net.JoinHostPort(c.Res.IP, strconv.Itoa(c.Res.Port)))

		if err == nil && r.Rcode == dns.RcodeSuccess {
			break
		}
	}

	if err !=nil {
		return err
	}
	if r.Rcode != dns.RcodeSuccess {
		return errors.New("Invalid answer name after TXT query")
	}

	for _, ans := range r.Answer {
		fmt.Printf("%v\n", ans)
		beg := strings.Index(ans.String(),"DNSC")
		fmt.Println(beg)
		if beg != -1 {
			c.certs = append(c.certs, ans.String()[beg:beg+124])
		}
		cert := ans.String()[beg:beg+124]
		fmt.Println(cert[:8])
		for idx, ch := range cert[:8] {
			fmt.Printf("%d %T %d\n", idx, ch, int(ch))
		}


	}
	return nil
}


