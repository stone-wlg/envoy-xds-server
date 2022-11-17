package utils

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/go-sql-driver/mysql"
)

var (
	db *sql.DB
)

func InitDatabase(config *XDSServerConfig) (err error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True",
		config.Mysql.User,
		config.Mysql.Password,
		config.Mysql.Host,
		config.Mysql.Port,
		config.Mysql.Database,
	)
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Printf("Init Database Failed, err:%v\n", err)
		return err
	}

	err = db.Ping()
	if err != nil {
		log.Printf("Init Database Failed, err:%v\n", err)
		return err
	}

	return nil
}

func GetPeers(sql string) []*Peer {
	var peers []*Peer
	rows, err := db.Query(sql)
	if err != nil {
		log.Printf("peer query failed, err:%v\n", err)
		return peers
	}

	for rows.Next() {
		var peer = Peer{}
		err := rows.Scan(&peer.PartyId, &peer.Type, &peer.Host, &peer.Port)
		if err != nil {
			log.Printf("peer scan failed, err:%v\n", err)
			return peers
		}
		peers = append(peers, &peer)
	}

	defer rows.Close()

	return peers
}

func GetServices(sql string) []*Service {
	var services []*Service
	rows, err := db.Query(sql)
	if err != nil {
		log.Printf("service query failed, err:%v\n", err)
		return services
	}

	for rows.Next() {
		var service = Service{}
		err := rows.Scan(&service.PartyId, &service.Type, &service.Host, &service.Port)
		if err != nil {
			log.Printf("service scan failed, err:%v\n", err)
			return services
		}
		services = append(services, &service)
	}

	defer rows.Close()

	return services
}
