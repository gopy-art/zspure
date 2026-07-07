package smtp

import (
	"fmt"
	"net"
	"zspure/modules/model"
)

type SmtpScanning struct {
	IP     net.IP `json:"ip,omitempty"`
	Port   int    `json:"port,omitempty"`
	Status string    `json:"status,omitempty"`
	Banner string `json:"banner,omitempty"`
	Sha256 string `json:"sha_256,omitempty"`

	Description     string `json:"description,omitempty"`
	DetectionPacket []byte `json:"detection_packet,omitempty"`
	BannerPacket    []byte `json:"banner_packet,omitempty"`
}

func (s *SmtpScanning) PrintInfo() {
	fmt.Println(s.Description)
}

func (s *SmtpScanning) SetDescription() {
	s.Description = "SMTP (Simple Mail Transfer Protocol) is the protocol used for sending emails from a client to a server, and between mail servers."
}

func (s *SmtpScanning) SetAddress(ip net.IP, port int)                {}
func (s *SmtpScanning) SetDetectionPacket(packet []byte)              {}
func (s *SmtpScanning) SetBannerPacket(packet []byte)                 {}
func (s *SmtpScanning) ServiceDetection(conn *net.Conn) (bool, error) { return false, nil }
func (s *SmtpScanning) BannerGathering(conn *net.Conn) (bool, error)  { return false, nil }
func (s *SmtpScanning) PrintResult() model.ScanStructure              { return model.ScanStructure{} }
