package devices

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

type UpnpDevices struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (u *UpnpDevices) SetCategory(category ...string) {
	u.Category = model.Category.Service()
}

func (u *UpnpDevices) SetDeviceName(device ...string) {
	u.DeviceName = "UPNP Devices"
}

func (u *UpnpDevices) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (u *UpnpDevices) Filters(banner map[string]interface{}) bool {
	if banner["headers"] == nil {
		return false
	}
	if val, ok := banner["headers"].(map[string]interface{})["server"]; ok {
		if strings.Contains(fmt.Sprintf("%v", val), "Upnp") {
			return true
		}
	}
	return false
}

func (u *UpnpDevices) DeviceScan(banner map[string]interface{}) bool {
	if val, ok := banner["headers"].(map[string]interface{})["server"].(string); ok && val != "" {
		if strings.Contains(val, "Upnp") {
			if strings.Contains(val, "/") {
				u.DeviceName = strings.Split(val, "/")[0]
				u.Version = strings.Split(val, "/")[1]
			} else {
				u.DeviceName = val
			}
		}
	}
	return false
}

func (u *UpnpDevices) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": u.DeviceName + " " + u.Version,
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
		url := fmt.Sprintf(model.CVE.MainResource(), strings.ToLower(strings.ReplaceAll(fmt.Sprintf("%v %v", u.DeviceName, u.Version), " ", "%20")))
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

	for _, vl := range CVE {
		u.CveList = append(u.CveList, vl.CVEID)
		totalScore += vl.BaseScore
	}

	u.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if u.CveScore > 7 {
		u.Sensibility = "HIGH"
	} else if u.CveScore >= 4 && u.CveScore <= 7 {
		u.Sensibility = "MEDIUM"
	} else if u.CveScore < 4 {
		u.Sensibility = "LOW"
	}
	u.CveList = utils.RemoveDuplicates(u.CveList)
}

func (u *UpnpDevices) PrintInfo() string { return model.Category.Service() + " | Upnp Devices" }

func (u *UpnpDevices) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    u.Category,
		DeviceName:  u.DeviceName,
		Version:     u.Version,
		CveList:     u.CveList,
		Sensibility: u.Sensibility,
		CveScore:    u.CveScore,
	}
}
