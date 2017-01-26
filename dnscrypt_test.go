package dnscrypt

import (
	"testing"
	"fmt"
)

func TestMagic(t *testing.T) {
	//p :=
	resolver := Resolver{Port:15353, IP:"77.88.8.78", PublicName:"2.dnscrypt-cert.browser.yandex.net"}
	client := Client{Res: &resolver}
	err := client.retrieveCertificates()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(client.certs)
}
