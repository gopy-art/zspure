package zxfs

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

type ZXFSFileSystem struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (z *ZXFSFileSystem) SetCategory(category ...string) {
	z.Category = model.Category.NetworkStorage()
}

func (z *ZXFSFileSystem) SetDeviceName(device ...string) {
	z.DeviceName = "ZXFS File System"
}

func (z *ZXFSFileSystem) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (z *ZXFSFileSystem) Filters(banner map[string]interface{}) bool {
	if banner["banner"] != nil &&
		banner["banner"].(string) != "" &&
		strings.Contains(strings.ToLower(banner["banner"].(string)), strings.ToLower("ZXFS Ftp Server")) {
		return true
	}
	return false
}

func (z *ZXFSFileSystem) DeviceScan(banner map[string]interface{}) bool {
	re := regexp.MustCompile(`ZXFS Ftp Server v([\d.]+)`)
	matches := re.FindStringSubmatch(banner["banner"].(string))
	if len(matches) > 1 {
		z.Version = matches[1]
		return true
	}
	return false
}

func (z *ZXFSFileSystem) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": fmt.Sprintf("zxfs %v", z.Version),
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
			strings.ToLower(strings.ReplaceAll(fmt.Sprintf("zxfs %v", z.Version), " ", "%20")))
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
		z.CveList = append(z.CveList, v.CVEID)
		totalScore += v.BaseScore
	}

	z.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if z.CveScore > 7 {
		z.Sensibility = "HIGH"
	} else if z.CveScore >= 4 && z.CveScore <= 7 {
		z.Sensibility = "MEDIUM"
	} else if z.CveScore < 4 {
		z.Sensibility = "LOW"
	}
	z.CveList = utils.RemoveDuplicates(z.CveList)
}

func (z *ZXFSFileSystem) PrintInfo() string {
	return model.Category.NetworkStorage() + " | ZXFS File System"
}

func (z *ZXFSFileSystem) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    z.Category,
		DeviceName:  z.DeviceName,
		Version:     z.Version,
		CveList:     z.CveList,
		Sensibility: z.Sensibility,
		CveScore:    z.CveScore,
	}
}
