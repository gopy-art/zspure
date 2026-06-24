package tnftpd

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

type TnftpdTcpService struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (t *TnftpdTcpService) SetCategory(category ...string) {
	t.Category = model.Category.Service()
}

func (t *TnftpdTcpService) SetDeviceName(device ...string) {
	t.DeviceName = "Tnftpd (portable version of the NetBSD)"
}

func (t *TnftpdTcpService) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (t *TnftpdTcpService) Filters(banner map[string]interface{}) bool {
	if banner["banner"] != nil && banner["banner"].(string) != "" && strings.Contains(banner["banner"].(string), "FTP server (tnftpd") {
		return true
	}
	return false
}

func (t *TnftpdTcpService) DeviceScan(banner map[string]interface{}) bool {
	t.ExtraInformation.NewExtraInfo()
	re := regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*\(tnftpd\s+([^)]+)\)`)
	matches := re.FindStringSubmatch(banner["banner"].(string))
	if len(matches) > 2 {
		t.ExtraInformation.SetExtraInfo("local_address", matches[1])
		t.Version = matches[2]
		return true
	}
	return false
}

func (t *TnftpdTcpService) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": fmt.Sprintf("tnftpd %v", t.Version),
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
			strings.ToLower(strings.ReplaceAll(fmt.Sprintf("tnftpd %v", t.Version), " ", "%20")))
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
		t.CveList = append(t.CveList, v.CVEID)
		totalScore += v.BaseScore
	}

	t.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if t.CveScore > 7 {
		t.Sensibility = "HIGH"
	} else if t.CveScore >= 4 && t.CveScore <= 7 {
		t.Sensibility = "MEDIUM"
	} else if t.CveScore < 4 {
		t.Sensibility = "LOW"
	}
	t.CveList = utils.RemoveDuplicates(t.CveList)
}

func (t *TnftpdTcpService) PrintInfo() string {
	return model.Category.Service() + " | Tnftpd (portable version of the NetBSD)"
}

func (t *TnftpdTcpService) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         t.Category,
		DeviceName:       t.DeviceName,
		Version:          t.Version,
		CveList:          t.CveList,
		Sensibility:      t.Sensibility,
		CveScore:         t.CveScore,
		ExtraInformation: t.ExtraInformation,
	}
}
