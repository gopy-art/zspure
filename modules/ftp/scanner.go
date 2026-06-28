package ftp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
	"zspure/modules/model"
)

type FtpScanning struct {
	IP     net.IP    `json:"ip,omitempty"`
	Port   int       `json:"port,omitempty"`
	Status string    `json:"status,omitempty"`
	Banner ftpBanner `json:"banner,omitempty"`
	Sha256 string    `json:"sha_256,omitempty"`

	Description     string `json:"description,omitempty"`
	DetectionPacket []byte `json:"detection_packet,omitempty"`
	BannerPacket    []byte `json:"banner_packet,omitempty"`
}

type ftpBanner struct {
	Banner string `json:"banner"`
	Sha256 string `json:"sha256"`
}

func (f *FtpScanning) PrintInfo() {
	fmt.Println(f.Description)
}

func (f *FtpScanning) SetDescription() {
	f.Description = "FTP (File Transfer Protocol) is a standard network protocol used to transfer files between a client and a server over TCP/IP."
}

func (f *FtpScanning) SetAddress(ip net.IP, port int) {
	f.IP = ip
	f.Port = port
}

func (f *FtpScanning) SetDetectionPacket(packet []byte) {
	if len(packet) == 0 || packet == nil {
		f.DetectionPacket = []byte(commands["HELP"])
	} else {
		f.DetectionPacket = packet
	}
}

func (f *FtpScanning) SetBannerPacket(packet []byte) {
	if len(packet) == 0 || packet == nil {
		f.BannerPacket = []byte(commands["PWD"])
	} else {
		f.BannerPacket = packet
	}
}

func (f *FtpScanning) ServiceDetection(conn *net.Conn) (bool, error) {
	if _, err := (*conn).Write(f.DetectionPacket); err != nil {
		return false, fmt.Errorf("Write error: %v", err)
	}
	response := make([]byte, 4096)
	n, err := (*conn).Read(response)
	if err != nil {
		return false, fmt.Errorf("Read error: %v", err)
	}
	if regexp.MustCompile(`^([1-5][0-9]{2}[- ]|220-|331-|421 )`).MatchString(string(response[:n])) {
		f.Banner.Banner = strings.TrimSuffix(string(response[:n]), "\r\n")
		hash := sha256.Sum256(response[:n])
		f.Banner.Sha256 = hex.EncodeToString(hash[:])
		f.Status = "success"
		return true, nil
	}
	f.Status = "failed"
	return false, nil
}

func (f *FtpScanning) BannerGathering(conn *net.Conn) (bool, error) {
	/*
		The FTP protocol is none probe and with the first packet it will give us the informatiom that we want, so in this protocol the ServiceDetection will do everything
	*/
	return true, nil
}

func (f *FtpScanning) PrintResult() model.ScanStructure {
	return model.ScanStructure{
		IP: f.IP,
		Data: model.ScanDataStructure{
			Status:    f.Status,
			Protocol:  "ftp",
			Port:      f.Port,
			Result:    f.Banner,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	}
}
