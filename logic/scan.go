package logic

import (
	"fmt"
	"net"
	"sync"
	"time"
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
}

func NewScanLogic() *ScanLogic {
	return new(ScanLogic)
}

func (s *ScanLogic) Init(target ScanInput, timeout time.Duration) {
	if _, _, err := net.ParseCIDR(target.Targets); err == nil {
		s.ChannelIP = make(chan ScanInput, 100)
		s.Targets = target.Targets
		s.Port = target.Port
		s.Timeout = timeout
	}
}

func (s *ScanLogic) StartScanner() (err error) {
	s.wg.Add(1)
    go s.targetHandler()
    err = s.targetProducer()
	s.wg.Wait()
	return
}

func (s *ScanLogic) open(ip string, port int) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), s.Timeout)
	if err != nil {
		return nil, fmt.Errorf("port closed")
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
            if nextIP[i] != 0 { break }
        }
        if !ipnet.Contains(nextIP) { break }
        ip = nextIP
    }
	close(s.ChannelIP)
	return nil
}

func (s *ScanLogic) targetHandler() {
	defer s.wg.Done()
	for target := range s.ChannelIP {
		_, err := s.open(target.Targets, target.Port)
		if err != nil {
            fmt.Printf("%v:%v %v\n", target.Targets, target.Port, err)
			continue
        }
		fmt.Printf("%v:%v is open\n", target.Targets, target.Port)
	}
}
