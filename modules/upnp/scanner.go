package upnp

import (
	"fmt"
	"net"
	"zspure/modules/model"
)

type UpnpScanning struct {
	IP     net.IP `json:"ip,omitempty"`
	Port   int    `json:"port,omitempty"`
	Status string    `json:"status,omitempty"`
	Banner string `json:"banner,omitempty"`
	Sha256 string `json:"sha_256,omitempty"`

	Description     string `json:"description,omitempty"`
	DetectionPacket []byte `json:"detection_packet,omitempty"`
	BannerPacket    []byte `json:"banner_packet,omitempty"`
}

func (u *UpnpScanning) PrintInfo() {
	fmt.Println(u.Description)
}

func (u *UpnpScanning) SetDescription() {
	u.Description = "UPnP (Universal Plug and Play) is a network protocol that allows devices to automatically discover and communicate with each other on a local network."
}

func (u *UpnpScanning) SetAddress(ip net.IP, port int)                {}
func (u *UpnpScanning) SetDetectionPacket(packet []byte)              {}
func (u *UpnpScanning) SetBannerPacket(packet []byte)                 {}
func (u *UpnpScanning) ServiceDetection(conn *net.Conn) (bool, error) { return false, nil }
func (u *UpnpScanning) BannerGathering(conn *net.Conn) (bool, error)  { return false, nil }
func (u *UpnpScanning) PrintResult() model.ScanStructure              { return model.ScanStructure{} }
