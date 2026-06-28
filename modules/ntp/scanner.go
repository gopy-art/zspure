package ntp

import (
	"fmt"
	"net"
	"zspure/modules/model"
)

type NtpScanning struct {
	IP     net.IP `json:"ip,omitempty"`
	Port   int    `json:"port,omitempty"`
	Status string    `json:"status,omitempty"`
	Banner string `json:"banner,omitempty"`
	Sha256 string `json:"sha_256,omitempty"`

	Description     string `json:"description,omitempty"`
	DetectionPacket []byte `json:"detection_packet,omitempty"`
	BannerPacket    []byte `json:"banner_packet,omitempty"`
}

func (n *NtpScanning) PrintInfo() {
	fmt.Println(n.Description)
}

func (n *NtpScanning) SetDescription() {
	n.Description = "NTP (Network Time Protocol) is a networking protocol used to synchronize the clocks of computers and devices over a packet-switched network."
}

func (n *NtpScanning) SetAddress(ip net.IP, port int)                {}
func (n *NtpScanning) SetDetectionPacket(packet []byte)              {}
func (n *NtpScanning) SetBannerPacket(packet []byte)                 {}
func (n *NtpScanning) ServiceDetection(conn *net.Conn) (bool, error) { return false, nil }
func (n *NtpScanning) BannerGathering(conn *net.Conn) (bool, error)  { return false, nil }
func (n *NtpScanning) PrintResult() model.ScanStructure              { return model.ScanStructure{} }