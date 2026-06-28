package logic

import (
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"sync"
	"time"
	"zspure/config"
	"zspure/config/cmd"
	"zspure/modules"
	"zspure/modules/model"
)

type ScanInput struct {
	Targets string
	Port    int
	Timeout time.Duration
}

type ScanLogic struct {
	ScanInput
	ChannelIP chan ScanInput
	wg        sync.WaitGroup
	mu        sync.Mutex
}

func NewScanLogic() *ScanLogic {
	return new(ScanLogic)
}

func (s *ScanLogic) Init(target ScanInput, timeout time.Duration) error {
	if _, _, err := net.ParseCIDR(target.Targets); err != nil {
		return fmt.Errorf("invalid CIDR: %w", err)
	}
	s.ChannelIP = make(chan ScanInput, 100)
	s.Targets = target.Targets
	s.Port = target.Port
	s.Timeout = timeout
	return nil
}

func (s *ScanLogic) StartScanner() error {
	s.wg.Add(1)
	go s.targetHandler()
	if err := s.targetProducer(); err != nil {
		return fmt.Errorf("producer error: %w", err)
	}
	s.wg.Wait()
	return nil
}

func (s *ScanLogic) open(ip string, port int) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), s.Timeout)
	if err != nil {
		return nil, fmt.Errorf("port %d closed on %s", port, ip)
	}
	return conn, nil
}

func (s *ScanLogic) targetProducer() error {
	_, ipnet, err := net.ParseCIDR(s.Targets)
	if err != nil {
		close(s.ChannelIP)
		return err
	}

	ip := ipnet.IP.Mask(ipnet.Mask)
	for {
		s.ChannelIP <- ScanInput{Targets: ip.String(), Port: s.Port, Timeout: s.Timeout}
		nextIP := make(net.IP, len(ip))
		copy(nextIP, ip)
		for i := len(nextIP) - 1; i >= 0; i-- {
			nextIP[i]++
			if nextIP[i] != 0 {
				break
			}
		}
		if !ipnet.Contains(nextIP) {
			break
		}
		ip = nextIP
	}
	close(s.ChannelIP)
	return nil
}

func (s *ScanLogic) targetHandler() {
	defer s.wg.Done()
	for target := range s.ChannelIP {
		conn, err := s.open(target.Targets, target.Port)
		if err != nil {
			cmd.InfoLogger.Printf("%v\n", err)
			continue
		}

		for _, pl := range modules.ModuleList {
			protocol, err := modules.NewScanner(pl)
			if err != nil {
				continue
			}

			protocol.SetAddress(net.ParseIP(target.Targets), target.Port)
			protocol.SetDetectionPacket(nil)
			protocol.SetBannerPacket(nil)

			serviceOK, errService := protocol.ServiceDetection(&conn)
			if !serviceOK || errService != nil {
				continue
			}

			bannerOK, errBanner := protocol.BannerGathering(&conn)
			if !bannerOK || errBanner != nil {
				continue
			}

			s.targetFingerprints(protocol)
		}
		conn.Close()
	}
}

func (s *ScanLogic) targetFingerprints(protocol model.Scan) {
	var wg sync.WaitGroup
	result := protocol.PrintResult()

	var banner map[string]interface{}
	jsonData, err := json.Marshal(result.Data.Result)
	if err != nil {
		cmd.ErrorLogger.Printf("marshal error: %v\n", err)
		return
	}

	if err := json.Unmarshal(jsonData, &banner); err != nil {
		cmd.ErrorLogger.Printf("unmarshal error: %v\n", err)
		return
	}

	handlers, _ := modules.NewModule(result.Data.Protocol)
	for chunk := range slices.Chunk(handlers, 10) {
		for _, device := range chunk {
			wg.Add(1)
			go func(d model.ModuleMethods) {
				defer wg.Done()
				s.processDevice(d, banner, result)
			}(device)
		}
		wg.Wait()
	}
}

func (s *ScanLogic) processDevice(device model.ModuleMethods, banner map[string]interface{}, result model.ScanStructure) {
	if !device.Filters(banner) {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	device.SetCategory()
	device.SetDeviceName()
	device.DeviceScan(banner)

	if config.FIND_CVE {
		device.CveScan(nil)
	}

	result.FingerPrints = device.Result()

	if config.JSON_OUTPUT {
		buf, err := json.Marshal(result)
		if err != nil {
			cmd.ErrorLogger.Printf("marshal error: %v\n", err)
			return
		}
		fmt.Printf("%s\n", buf)
	} else {
		fmt.Printf("Address : %v:%d\nProtocol: %v\nStatus: %v\nBanner: %+v\nDevice Name: %v\nCategory: %v\nVersion: %v\n",
			s.Targets,
			s.Port,
			result.Data.Protocol,
			result.Data.Status,
			banner,
			result.FingerPrints.DeviceName,
			result.FingerPrints.Category,
			result.FingerPrints.Version)
	}
}
