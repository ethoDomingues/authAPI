package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

var db *gorm.DB

type Jsonify interface {
	ToJson() any
}

type ManyJsonify[C Jsonify] []C

func (mj ManyJsonify[C]) ToJson() any {
	m := []any{}
	for _, v := range mj {
		m = append(m, v.ToJson())
	}
	return m
}

func DBSession() *gorm.DB {
	if db == nil {
		var err error
		uri := "dbs/auth.db"
		db, err = gorm.Open(
			sqlite.Open(uri),
			&gorm.Config{
				NamingStrategy: NamingStrategyLocal{},
			},
		)
		if err != nil {
			panic(err)
		}
	}
	return db.Session(&gorm.Session{})
}

type NamingStrategyLocal struct {
	schema.NamingStrategy
}

func (ns NamingStrategyLocal) ColumnName(table string, column string) string {
	return column
}

type Model struct {
	ID        int `gorm:"primarykey"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`

	UUID string
}

func (m *Model) BeforeCreate(tx *gorm.DB) (err error) {
	m.UUID = uuid.New().String()
	return
}

func (m *Model) Created() string {
	return m.CreatedAt.Format("RFC3339")
}

func (m *Model) Updated() string {
	return m.UpdatedAt.Format("RFC3339")
}

func (m *Model) Deleted() string {
	return m.DeletedAt.Time.Format("RFC3339")
}
func (m *Model) ToMap() map[string]any {
	return map[string]any{
		"id":        m.UUID,
		"createdAt": m.CreatedAt.UTC().UnixMilli(),
	}
}

func (m *Model) ToJson() any {
	return m.ToMap()
}
