package main

import (
	"database/sql"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
)

type User struct {
	id    int
	name  string
	age   int
	birth string
}

func main() {
	dsn := "root:root@tcp(127.0.0.1:3306)/test?charset=utf8mb4&parseTime=True"
	db, e := sql.Open("mysql", dsn)
	ErrorCheck(e)

	// close database after all work is done
	defer db.Close()

	PingDB(db)

	// INSERT INTO DB
	// prepare
	stmt, e := db.Prepare("INSERT INTO `test`.`user`(id, name, age, birth) values (?, ?, ?, ?)")
	ErrorCheck(e)

	//execute
	res, e := stmt.Exec("5", "xm", "30", "2022-01-01 01:02:03")
	ErrorCheck(e)

	id, e := res.LastInsertId()
	ErrorCheck(e)

	fmt.Println("Insert id", id)

	//Update db
	stmt, e = db.Prepare("UPDATE `test`.`user` SET age = ? where id = ?")
	ErrorCheck(e)

	// execute
	res, e = stmt.Exec("35", "5")
	ErrorCheck(e)

	a, e := res.RowsAffected()
	ErrorCheck(e)

	fmt.Println(a)

	// query all data
	rows, e := db.Query("SELECT * FROM `test`.`user`")
	ErrorCheck(e)

	var user = User{}

	for rows.Next() {
		e = rows.Scan(&user.id, &user.name, &user.age, &user.birth)
		ErrorCheck(e)
		fmt.Println(user)
	}

	// delete data
	stmt, e = db.Prepare("DELETE FROM `test`.`user` WHERE id = ?")
	ErrorCheck(e)

	// delete 5th post
	res, e = stmt.Exec("5")
	ErrorCheck(e)

	// affected rows
	a, e = res.RowsAffected()
	ErrorCheck(e)

	fmt.Println(a) // 1
}

func ErrorCheck(err error) {
	if err != nil {
		panic(err.Error())
	}
}

func PingDB(db *sql.DB) {
	err := db.Ping()
	ErrorCheck(err)
}
