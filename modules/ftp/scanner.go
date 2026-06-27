package ftp

import (
	"fmt"
	"net"
	"zspure/modules/model"
)

type FtpScanning struct {
	IP     net.IP `json:"ip,omitempty"`
	Port   int    `json:"port,omitempty"`
	Banner string `json:"banner,omitempty"`
	Sha256 string `json:"sha_256,omitempty"`

	Description     string `json:"description,omitempty"`
	DetectionPacket []byte `json:"detection_packet,omitempty"`
	BannerPacket    []byte `json:"banner_packet,omitempty"`
}

func (f *FtpScanning) PrintInfo() {
	fmt.Println(f.Description)
}

func (f *FtpScanning) SetDescription() {
	f.Description = "FTP (File Transfer Protocol) is a standard network protocol used to transfer files between a client and a server over TCP/IP."
}

func (f *FtpScanning) SetAddress(ip net.IP, port int)                {}
func (f *FtpScanning) SetDetectionPacket(packet []byte)              {}
func (f *FtpScanning) SetBannerPacket(packet []byte)                 {}
func (f *FtpScanning) ServiceDetection(conn *net.Conn) (bool, error) { return false, nil }
func (f *FtpScanning) BannerGathering(conn *net.Conn) (bool, error)  { return false, nil }
func (f *FtpScanning) PrintResult() model.ScanStructure              { return model.ScanStructure{} }
