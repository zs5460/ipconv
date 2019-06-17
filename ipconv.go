package ipconv

import (
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"
)

func IP2Long(ip net.IP) uint {
	return (uint(ip[12]) << 24) + (uint(ip[13]) << 16) + (uint(ip[14]) << 8) + uint(ip[15])
}

func Long2IP(long uint) net.IP {
	return net.IPv4(byte(long>>24), byte(long>>16), byte(long>>8), byte(long))
}

func CIDR2IPS(ipr string) (ips []string, err error) {
	ip, ipnet, err := net.ParseCIDR(ipr)
	if err != nil {
		return nil, err
	} else if !ip.Equal(ipnet.IP) {
		return nil, errors.New("Invalid CIDR")
	}

	var iprangeMask int
	if slashPos := strings.LastIndex(ipr, "/"); slashPos == -1 {
		iprangeMask = 32
	} else {
		iprangeMask, err = strconv.Atoi(ipr[slashPos+1:])
		if err != nil {
			return nil, err
		}
	}

	if err != nil {
		return nil, err
	} else if iprangeMask > 32 {
		return nil, errors.New("Invalid block size")
	}

	ipstart := IP2Long(ip)
	ipend := IP2Long(ip) + (1 << uint(32-iprangeMask)) - 1
	for curip := ipstart; curip <= ipend; curip++ {
		ips = append(ips, Long2IP(curip).String())
	}

	return ips, nil
}

func DUAN2IPS(ipd string) (ips []string, err error) {
	reg := regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}$`)
	if !reg.MatchString(ipd) {
		return nil, errors.New("Invalid ip format")
	}
	tmpIP := strings.Split(ipd, ".")
	prefix := tmpIP[0] + "." + tmpIP[1] + "." + tmpIP[2] + "."
	start, err := strconv.Atoi(strings.Split(tmpIP[3], "-")[0])
	if err != nil {
		return nil, err
	}
	end, err := strconv.Atoi(strings.Split(tmpIP[3], "-")[1])
	if err != nil {
		return nil, err
	}
	if start >= end || start > 254 || end > 255 {
		return nil, errors.New("Invalid ip format")
	}
	for i := start; i <= end; i++ {
		ip := prefix + strconv.Itoa(i)
		ips = append(ips, ip)
	}
	return ips, nil
}
