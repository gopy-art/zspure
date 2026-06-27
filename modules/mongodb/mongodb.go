package mongodb

import (
	"zspure/modules/model"
	"zspure/modules/mongodb/database"
)

func NewMONGODB() []model.ModuleMethods {
	return []model.ModuleMethods{
		&database.MongoDatabase{},
	}
}

func NewMongoDBScanner() *MongoDBScanning {
	return new(MongoDBScanning)
}
