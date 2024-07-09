package main

import (
	"DNS_Resolver/client"
	"DNS_Resolver/resolver"
	"bytes"
	"fmt"
	"os"
)

type DNSPacket struct {
	header      *resolver.Header
	questions   []*resolver.Question
	answers     []*resolver.Record
	additionals []*resolver.Record
	authorities []*resolver.Record
}

func main() {
	domains := os.Args[1:]
	if len(domains) < 1 {
		fmt.Println("Usage: ./dns <domain> [<domain> ...]")
		os.Exit(0)
	}

	for _, domain := range domains {
		fmt.Println(resolve(domain, resolver.TYPE_A))
	}
}

func resolve(domainName string, questionType uint16) string {
	nameServer := "198.41.0.4"
	for {
		fmt.Printf("Querying %s for %s\n", nameServer, domainName)
		dnsResponse := sendQuery(nameServer, domainName, questionType)
		dnsPacket := getDnsPacketFromResponse(dnsResponse)

		if ip := getAnswer(dnsPacket.answers); ip != "" {
			return ip
		}

		if nsIp := getNameServerIp(dnsPacket.additionals); nsIp != "" {
			nameServer = nsIp
			continue
		}

		if nsDomain := getNameServer(dnsPacket.authorities); nsDomain != "" {
			nameServer = resolve(nsDomain, resolver.TYPE_A)
		}
	}
}

func sendQuery(nameServer, domainName string, questionType uint16) []byte {
	query := resolver.NewQuery(
		resolver.NewHeader(22, 0, 1, 0, 0, 0),
		resolver.NewQuestion(domainName, questionType, resolver.CLASS_IN),
	)

	client := client.NewClient(nameServer, 53)
	return client.SendQuery(query)
}

func getDnsPacketFromResponse(dnsResponse []byte) *DNSPacket {
	var (
		header      *resolver.Header
		questions   []*resolver.Question
		answers     []*resolver.Record
		authorities []*resolver.Record
		additionals []*resolver.Record
	)

	reader := bytes.NewReader(dnsResponse)
	header, err := resolver.ParseHeader(reader)
	if err != nil {
		fmt.Printf("Can't parse the response header: %v\n", err)
		os.Exit(-1)
	}
	for range header.QdCount {
		questions = append(questions, resolver.ParseQuestion(reader))
	}

	for range header.AnCount {
		answers = append(answers, resolver.ParseRecord(reader))
	}

	for range header.NsCount {
		authorities = append(authorities, resolver.ParseRecord(reader))
	}

	for range header.ArCount {
		additionals = append(additionals, resolver.ParseRecord(reader))
	}

	return &DNSPacket{
		header:      header,
		questions:   questions,
		answers:     answers,
		authorities: authorities,
		additionals: additionals,
	}
}

func getAnswer(answers []*resolver.Record) string {
	return getRecord(answers)
}

func getNameServerIp(additionals []*resolver.Record) string {
	return getRecord(additionals)
}

func getNameServer(authorities []*resolver.Record) string {
	return getRecord(authorities)
}

func getRecord(records []*resolver.Record) string {
	for _, record := range records {
		if record.Type == resolver.TYPE_A || record.Type == resolver.TYPE_NS {
			return record.Rdata
		}
	}
	return ""
}
