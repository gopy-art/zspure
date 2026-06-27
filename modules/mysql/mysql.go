package mysql

import (
	"zspure/modules/model"
	database "zspure/modules/mysql/Database"
)

func NewMYSQL() []model.ModuleMethods {
	return []model.ModuleMethods{
		&database.MYSQLDatabase{},
	}
}

func NewMysqlScanner() *MysqlScanning {
	return new(MysqlScanning)
}
