package imap

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
	"zspure/modules/model"
)

type ImapScanning struct {
	IP     net.IP     `json:"ip,omitempty"`
	Port   int        `json:"port,omitempty"`
	Status string     `json:"status,omitempty"`
	Banner imapBanner `json:"banner,omitempty"`

	Description     string `json:"description,omitempty"`
	DetectionPacket []byte `json:"detection_packet,omitempty"`
	BannerPacket    []byte `json:"banner_packet,omitempty"`
}

type imapBanner struct {
	Banner string `json:"banner"`
	Sha256 string `json:"sha256"`
}

func (i *ImapScanning) PrintInfo() {
	fmt.Println(i.Description)
}

func (i *ImapScanning) SetDescription() {
	i.Description = "IMAP (Internet Message Access Protocol) is an email protocol that allows you to access and manage emails stored on a mail server from multiple devices."
}

func (i *ImapScanning) SetAddress(ip net.IP, port int) {
	i.IP = ip
	i.Port = port
}

func (i *ImapScanning) SetDetectionPacket(packet []byte) {
	if len(packet) == 0 || packet == nil {
		i.DetectionPacket = []byte("a001 CAPABILITY\r\n")
	} else {
		i.DetectionPacket = packet
	}
}

func (i *ImapScanning) SetBannerPacket(packet []byte) {
	if len(packet) == 0 || packet == nil {
		i.BannerPacket = []byte("\r\n")
	} else {
		i.BannerPacket = packet
	}
}

func (i *ImapScanning) ServiceDetection(conn *net.Conn) (bool, error) {
	if _, err := (*conn).Write(i.DetectionPacket); err != nil {
		return false, fmt.Errorf("Write error: %v", err)
	}
	response := make([]byte, 4096)
	n, err := (*conn).Read(response)
	if err != nil {
		return false, fmt.Errorf("Read error: %v", err)
	}
	if VerifyIMAPContents(string(response[:n])) {
		i.Banner.Banner = strings.TrimSuffix(string(response[:n]), "\r\n")
		hash := sha256.Sum256(response[:n])
		i.Banner.Sha256 = hex.EncodeToString(hash[:])
		i.Status = "success"
		return true, nil
	}
	i.Status = "failed"
	return false, nil
}

func (i *ImapScanning) BannerGathering(conn *net.Conn) (bool, error) {
	/*
		The IMAP protocol is none probe and with the first packet it will give us the informatiom that we want, so in this protocol the ServiceDetection will do everything
	*/
	return true, nil
}

func (i *ImapScanning) PrintResult() model.ScanStructure {
	return model.ScanStructure{
		IP: i.IP,
		Data: model.ScanDataStructure{
			Status:    i.Status,
			Protocol:  "imap",
			Port:      i.Port,
			Result:    i.Banner,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	}
}
