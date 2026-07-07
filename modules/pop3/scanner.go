package pop3

import (
	"fmt"
	"net"
	"zspure/modules/model"
)

type Pop3Scanning struct {
	IP     net.IP `json:"ip,omitempty"`
	Port   int    `json:"port,omitempty"`
	Status string    `json:"status,omitempty"`
	Banner string `json:"banner,omitempty"`
	Sha256 string `json:"sha_256,omitempty"`

	Description     string `json:"description,omitempty"`
	DetectionPacket []byte `json:"detection_packet,omitempty"`
	BannerPacket    []byte `json:"banner_packet,omitempty"`
}

func (p *Pop3Scanning) PrintInfo() {
	fmt.Println(p.Description)
}

func (p *Pop3Scanning) SetDescription() {
	p.Description = "POP3 (Post Office Protocol version 3) is an email protocol that downloads emails from a mail server to your local device and typically deletes them from the server."
}

func (p *Pop3Scanning) SetAddress(ip net.IP, port int)                {}
func (p *Pop3Scanning) SetDetectionPacket(packet []byte)              {}
func (p *Pop3Scanning) SetBannerPacket(packet []byte)                 {}
func (p *Pop3Scanning) ServiceDetection(conn *net.Conn) (bool, error) { return false, nil }
func (p *Pop3Scanning) BannerGathering(conn *net.Conn) (bool, error)  { return false, nil }
func (p *Pop3Scanning) PrintResult() model.ScanStructure              { return model.ScanStructure{} }
