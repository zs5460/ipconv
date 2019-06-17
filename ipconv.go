package ipconv

import (
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"
)

var (
	rePureIP  *regexp.Regexp
	reCIDR    *regexp.Regexp
	reIPRange *regexp.Regexp
)

func init() {
	rePureIP = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)
	reCIDR = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{2}$`)
	reIPRange = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}$`)
}

// IP2Long convert a ip to a uint.
func IP2Long(ip net.IP) uint {
	return (uint(ip[12]) << 24) + (uint(ip[13]) << 16) + (uint(ip[14]) << 8) + uint(ip[15])
}

// Long2IP convert a uint to a ip.
func Long2IP(long uint) net.IP {
	return net.IPv4(byte(long>>24), byte(long>>16), byte(long>>8), byte(long))
}

// CIDR2IPS returns a ip list if CIDR.
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

	if iprangeMask > 32 || iprangeMask < 16 {
		return nil, errors.New("Invalid Mask")
	}

	ipstart := IP2Long(ip)
	hostCount := (1 << uint(32-iprangeMask)) - 1
	for i := 0; i <= hostCount; i++ {
		ips = append(ips, Long2IP(ipstart+uint(i)).String())
	}

	return ips, nil
}

// Range2IPS returns a ip list of a iprange
func Range2IPS(ipr string) (ips []string, err error) {
	reg := regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}$`)
	if !reg.MatchString(ipr) {
		return nil, errors.New("Invalid ip-range")
	}
	tmp := strings.Split(ipr, "-")[0]
	if net.ParseIP(tmp) == nil {
		return nil, errors.New("Invalid start ip")
	}

	tmpIP := strings.Split(ipr, ".")
	prefix := tmpIP[0] + "." + tmpIP[1] + "." + tmpIP[2] + "."
	start, err := strconv.Atoi(strings.Split(tmpIP[3], "-")[0])
	if err != nil {
		return nil, err
	}
	end, err := strconv.Atoi(strings.Split(tmpIP[3], "-")[1])
	if err != nil {
		return nil, err
	}
	if end < start || end > 255 {
		return nil, errors.New("Invalid end ip")
	}
	for i := start; i <= end; i++ {
		ip := prefix + strconv.Itoa(i)
		ips = append(ips, ip)
	}
	return ips, nil
}

// Parse parse a ip such as ip,CIDR,ip-range and returns ip list
func Parse(ip string) ([]string, error) {
	if rePureIP.MatchString(ip) {
		return []string{ip}, nil
	} else if reCIDR.MatchString(ip) {
		return CIDR2IPS(ip)
	} else if reIPRange.MatchString(ip) {
		return Range2IPS(ip)
	} else {
		return nil, errors.New("Invalid IP")
	}
}
