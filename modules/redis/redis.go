package redis

import (
	"zspure/modules/model"
	database "zspure/modules/redis/Database"
)

func NewRedis() []model.ModuleMethods {
	return []model.ModuleMethods{
		&database.RedisDatabase{},
	}
}