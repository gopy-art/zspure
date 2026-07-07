package imap

import (
	"fmt"
	"net"
	"zspure/modules/model"
)

type ImapScanning struct {
	IP     net.IP `json:"ip,omitempty"`
	Port   int    `json:"port,omitempty"`
	Status string    `json:"status,omitempty"`
	Banner string `json:"banner,omitempty"`
	Sha256 string `json:"sha_256,omitempty"`

	Description     string `json:"description,omitempty"`
	DetectionPacket []byte `json:"detection_packet,omitempty"`
	BannerPacket    []byte `json:"banner_packet,omitempty"`
}

func (i *ImapScanning) PrintInfo() {
	fmt.Println(i.Description)
}

func (i *ImapScanning) SetDescription() {
	i.Description = "IMAP (Internet Message Access Protocol) is an email protocol that allows you to access and manage emails stored on a mail server from multiple devices."
}

func (i *ImapScanning) SetAddress(ip net.IP, port int)                {}
func (i *ImapScanning) SetDetectionPacket(packet []byte)              {}
func (i *ImapScanning) SetBannerPacket(packet []byte)                 {}
func (i *ImapScanning) ServiceDetection(conn *net.Conn) (bool, error) { return false, nil }
func (i *ImapScanning) BannerGathering(conn *net.Conn) (bool, error)  { return false, nil }
func (i *ImapScanning) PrintResult() model.ScanStructure              { return model.ScanStructure{} }
