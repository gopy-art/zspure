package mssql

import (
	"zspure/modules/model"
	database "zspure/modules/mssql/Database"
)

func NewMSSQL() []model.ModuleMethods {
	return []model.ModuleMethods{
		&database.MsSQLDatabase{},
	}
}