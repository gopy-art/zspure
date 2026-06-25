package netgear

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"zspure/config"
	"zspure/config/cmd"
	"zspure/handler"
	"zspure/modules/model"
	"zspure/utils"
)

type NetGearReadyNAS struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (n *NetGearReadyNAS) SetCategory(category ...string) {
	n.Category = model.Category.NetworkStorage()
}

func (n *NetGearReadyNAS) SetDeviceName(device ...string) {
	n.DeviceName = "Netgear ReadyNAS"
}

func (n *NetGearReadyNAS) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (n *NetGearReadyNAS) Filters(banner map[string]interface{}) bool {
	if banner["banner"] != nil && banner["banner"].(string) != "" && strings.Contains(strings.ToLower(banner["banner"].(string)), strings.ToLower("(NETGEAR ReadyNAS)")) {
		return true
	}
	return false
}

func (n *NetGearReadyNAS) DeviceScan(banner map[string]interface{}) bool {
	n.ExtraInformation.NewExtraInfo()
	versionRe := regexp.MustCompile(`ProFTPD\s+([\d.]+[a-z]*)`)
	if matches := versionRe.FindStringSubmatch(banner["banner"].(string)); len(matches) > 1 {
		n.Version = matches[1]
	}

	// Extract local IP: handles multiple formats
	// Pattern 1: [::ffff:192.168.1.112]
	// Pattern 2: [192.168.0.88]
	// Pattern 3: plain IP
	ipRe := regexp.MustCompile(`\[::ffff:([\d.]+)\]|\[([\d.]+)\]|\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)
	matches := ipRe.FindStringSubmatch(banner["banner"].(string))
	if len(matches) > 1 {
		if matches[1] != "" {
			n.ExtraInformation.SetExtraInfo("local_ip", matches[1])
		} else if matches[2] != "" {
			n.ExtraInformation.SetExtraInfo("local_ip", matches[2])
		} else if matches[3] != "" {
			n.ExtraInformation.SetExtraInfo("local_ip", matches[3])
		}
	}
	return false
}

func (n *NetGearReadyNAS) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": fmt.Sprintf("%v %v", n.DeviceName, n.Version),
		}))
		if len(result) == 0 {
			return
		}
		for _, c := range result {
			if len(CVE) == 10 {
				break
			}
			cveMod := model.NewCVEStructure(c)
			CVE = append(CVE, cveMod)
		}
	} else if config.FIND_CVE {
		url := fmt.Sprintf(model.CVE.MainResource(),
			strings.ToLower(strings.ReplaceAll(fmt.Sprintf("%v %v", n.DeviceName, n.Version), " ", "%20")))
		recieve, err := utils.GatherCVEOnline(url)
		if err != nil {
			cmd.ErrorLogger.Println("[CVE] error in gather the CVE for this device. (Server error)")
			return
		}
		CVE = append(CVE, recieve...)
	}

	if len(CVE) == 0 {
		cmd.InfoLogger.Println("[CVE] do not find any CVE for this module.")
		return
	}

	for _, v := range CVE {
		n.CveList = append(n.CveList, v.CVEID)
		totalScore += v.BaseScore
	}

	n.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if n.CveScore > 7 {
		n.Sensibility = "HIGH"
	} else if n.CveScore >= 4 && n.CveScore <= 7 {
		n.Sensibility = "MEDIUM"
	} else if n.CveScore < 4 {
		n.Sensibility = "LOW"
	}
	n.CveList = utils.RemoveDuplicates(n.CveList)
}

func (n *NetGearReadyNAS) PrintInfo() string {
	return model.Category.NetworkStorage() + " | Netgear ReadyNAS"
}

func (n *NetGearReadyNAS) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         n.Category,
		DeviceName:       n.DeviceName,
		Version:          n.Version,
		CveList:          n.CveList,
		Sensibility:      n.Sensibility,
		CveScore:         n.CveScore,
		ExtraInformation: n.ExtraInformation,
	}
}
