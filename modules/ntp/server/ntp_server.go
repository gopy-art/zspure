package server

import (
	"fmt"
	"strconv"
	"strings"
	"zspure/config"
	"zspure/config/cmd"
	"zspure/handler"
	"zspure/modules/model"
	"zspure/utils"
)

type NTPServer struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (n *NTPServer) SetCategory(category ...string) {
	n.Category = model.Category.Service()
}

func (n *NTPServer) SetDeviceName(device ...string) {
	n.DeviceName = "NTP Server"
}

func (a *NTPServer) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (n *NTPServer) Filters(banner map[string]interface{}) bool {
	if banner["time"] == nil {
		return false
	}
	if val, ok := banner["time"].(string); ok {
		if val != "" {
			return true
		}
	}
	return false
}

func (n *NTPServer) DeviceScan(banner map[string]interface{}) bool {
	if val, ok := banner["version"].(float64); ok && val != 0 {
		n.Version = fmt.Sprintf("%v", val)
	}

	return false
}

func (n *NTPServer) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": fmt.Sprintf("ntp %s", n.Version),
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
			strings.ToLower(strings.ReplaceAll(fmt.Sprintf("ntp %v", n.Version), " ", "%20")))
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

func (n *NTPServer) PrintInfo() string { return model.Category.Service() + " | NTP Server" }

func (n *NTPServer) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    n.Category,
		DeviceName:  n.DeviceName,
		Version:     n.Version,
		CveList:     n.CveList,
		Sensibility: n.Sensibility,
		CveScore:    n.CveScore,
	}
}
