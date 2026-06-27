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

func NewMSSQLScanner() *MssqlScanning {
	return new(MssqlScanning)
}
