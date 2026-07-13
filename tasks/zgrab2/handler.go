package zgrab2

import (
	"slices"
	"sync"
	"zspure/config"
	"zspure/modules"
	"zspure/modules/model"
	"zspure/utils"
)

func ParseZgrabInput(content []byte) (*ZgrabModel, error) {
	model := ZgrabModel{}
	err := model.Parse(content)
	return &model, err
}

func DetectZgrabResult(data zgrabDataModel) error {
	var wg sync.WaitGroup
	m := model.GatherModuleSructure{
		Protocol: data.Protocol,
		Banner:   data.Result,
	}

	handlers, err := modules.NewModule(m.Protocol)
	if err != nil {
		return err
	} else {
		for devices := range slices.Chunk(handlers, 10) {
			for _, device := range devices {
				wg.Go(func() {
					if res := device.Filters(m.Banner); res {
						device.SetCategory()
						device.SetDeviceName()
						device.DeviceScan(m.Banner)
						if config.FIND_CVE {
							device.CveScan(nil)
						}

						utils.NormalizeOutput(device.Result())
					}
				})
			}
			wg.Wait()
		}
	}
	return nil
}
