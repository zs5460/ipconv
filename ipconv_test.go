package ipconv

import (
	"net"
	"reflect"
	"testing"
)

func TestCIDR2IPS(t *testing.T) {
	type args struct {
		ipr string
	}
	tests := []struct {
		name    string
		args    args
		wantIps []string
		wantErr bool
	}{
		{
			name:    "normal",
			args:    args{"172.16.0.0/30"},
			wantIps: []string{"172.16.0.0", "172.16.0.1", "172.16.0.2", "172.16.0.3"},
			wantErr: false,
		},
		{
			name:    "invalid IP",
			args:    args{"172.16.0/24"},
			wantIps: nil,
			wantErr: true,
		},
		{
			name:    "invalid CIDR",
			args:    args{"172.16.0.2/24"},
			wantIps: nil,
			wantErr: true,
		},
		{
			name:    "invalid mask",
			args:    args{"172.16.0.0/12"},
			wantIps: nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIps, err := CIDR2IPS(tt.args.ipr)
			if (err != nil) != tt.wantErr {
				t.Errorf("CIDR2IPS() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotIps, tt.wantIps) {
				t.Errorf("CIDR2IPS() = %v, want %v", gotIps, tt.wantIps)
			}
		})
	}
}

func TestRange2IPS(t *testing.T) {
	type args struct {
		ipr string
	}
	tests := []struct {
		name    string
		args    args
		wantIps []string
		wantErr bool
	}{
		{
			name:    "normal",
			args:    args{"172.16.0.1-4"},
			wantIps: []string{"172.16.0.1", "172.16.0.2", "172.16.0.3", "172.16.0.4"},
			wantErr: false,
		},
		{
			name:    "invalid ip-range",
			args:    args{"172.16.0.12"},
			wantIps: nil,
			wantErr: true,
		},
		{
			name:    "invalid start IP",
			args:    args{"172.16.0.256-10"},
			wantIps: nil,
			wantErr: true,
		},
		{
			name:    "invalid IP",
			args:    args{"172.16.0.12-10"},
			wantIps: nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIps, err := Range2IPS(tt.args.ipr)
			if (err != nil) != tt.wantErr {
				t.Errorf("Range2IPS() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotIps, tt.wantIps) {
				t.Errorf("Range2IPS() = %v, want %v", gotIps, tt.wantIps)
			}
		})
	}
}

func TestIP2Long(t *testing.T) {
	type args struct {
		ip net.IP
	}
	tests := []struct {
		name string
		args args
		want uint
	}{
		{"normal", args{net.ParseIP("172.16.0.0")}, 2886729728},
		{"normal", args{net.ParseIP("172.16.0.1")}, 2886729729},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IP2Long(tt.args.ip); got != tt.want {
				t.Errorf("IP2Long() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLong2IP(t *testing.T) {
	type args struct {
		long uint
	}
	tests := []struct {
		name string
		args args
		want net.IP
	}{
		{"normal", args{2886729728}, net.ParseIP("172.16.0.0")},
		{"normal", args{2886729729}, net.ParseIP("172.16.0.1")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Long2IP(tt.args.long); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Long2IP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParse(t *testing.T) {
	type args struct {
		ip string
	}
	tests := []struct {
		name    string
		args    args
		wantIps []string
		wantErr bool
	}{
		{
			name:    "pureIP",
			args:    args{"172.16.0.1"},
			wantIps: []string{"172.16.0.1"},
			wantErr: false,
		},
		{
			name:    "CIDR",
			args:    args{"172.16.0.0/30"},
			wantIps: []string{"172.16.0.0", "172.16.0.1", "172.16.0.2", "172.16.0.3"},
			wantErr: false,
		},
		{
			name:    "ipRange",
			args:    args{"172.16.0.1-4"},
			wantIps: []string{"172.16.0.1", "172.16.0.2", "172.16.0.3", "172.16.0.4"},
			wantErr: false,
		},
		{
			name:    "error",
			args:    args{"172.16.0.1.4"},
			wantIps: nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.args.ip)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.wantIps) {
				t.Errorf("Parse() = %v, want %v", got, tt.wantIps)
			}
		})
	}
}
