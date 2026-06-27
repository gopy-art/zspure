package pptp

import (
	"fmt"
	"net"
	"zspure/modules/model"
)

type PPTPScanning struct {
	IP     net.IP `json:"ip,omitempty"`
	Port   int    `json:"port,omitempty"`
	Banner string `json:"banner,omitempty"`
	Sha256 string `json:"sha_256,omitempty"`

	Description     string `json:"description,omitempty"`
	DetectionPacket []byte `json:"detection_packet,omitempty"`
	BannerPacket    []byte `json:"banner_packet,omitempty"`
}

func (p *PPTPScanning) PrintInfo() {
	fmt.Println(p.Description)
}

func (p *PPTPScanning) SetDescription() {
	p.Description = "PPTP (Point-to-Point Tunneling Protocol) is an obsolete VPN protocol that creates a secure tunnel over IP networks."
}

func (p *PPTPScanning) SetAddress(ip net.IP, port int)                {}
func (p *PPTPScanning) SetDetectionPacket(packet []byte)              {}
func (p *PPTPScanning) SetBannerPacket(packet []byte)                 {}
func (p *PPTPScanning) ServiceDetection(conn *net.Conn) (bool, error) { return false, nil }
func (p *PPTPScanning) BannerGathering(conn *net.Conn) (bool, error)  { return false, nil }
func (p *PPTPScanning) PrintResult() model.ScanStructure              { return model.ScanStructure{} }