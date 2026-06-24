package schniderelectric

import "strings"

var SchneiderGateways []string = []string{
	"bmx p34",
	"bmx nor",
	"noe",
	"sas tsx",
	"sr3 net",
	"otb",
}

func findIndices(slice []string, s string) []string {
	var indices []string
	for _, substr := range slice {
		if strings.Contains(s, substr) {
			indices = append(indices, substr)
		}
	}
	return indices
}