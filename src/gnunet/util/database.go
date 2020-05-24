// This file is part of gnunet-go, a GNUnet-implementation in Golang.
// Copyright (C) 2019, 2020 Bernd Fix  >Y<
//
// gnunet-go is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License,
// or (at your option) any later version.
//
// gnunet-go is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL3.0-or-later

package util

import (
	"database/sql"
	"fmt"
	"os"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/mattn/go-sqlite3"
)

// Error messages related to databases
var (
	ErrSqlInvalidDatabaseSpec = fmt.Errorf("Invalid database specification")
	ErrSqlNoDatabase          = fmt.Errorf("Database not found")
)

// ConnectSqlDatabase connects to an SQL database (various types and flavors):
// The 'spec' option defines the arguments required to connect to a database;
// the meaning and format of the arguments depends on the specific SQL database.
// The arguments are seperated by the '+' character; the first (and mandatory)
// argument defines the SQL database type. Other arguments depend on the value
// of this first argument.
// The following SQL types are implemented:
// * 'sqlite3': SQLite3-compatible database; the second argument specifies the
//              file that holds the data (e.g. "sqlite3+/home/user/store.db")
// * 'mysql':   A MySQL-compatible database; the second argument specifies the
//              information required to log into the database (e.g.
//              "[user[:passwd]@][proto[(addr)]]/dbname[?param1=value1&...]").
func ConnectSqlDatabase(spec string) (db *sql.DB, err error) {
	// split spec string into segments
	specs := strings.Split(spec, ":")
	if len(specs) < 2 {
		return nil, ErrSqlInvalidDatabaseSpec
	}
	switch specs[0] {
	case "sqlite3":
		// check if the database file exists
		var fi os.FileInfo
		if fi, err = os.Stat(specs[1]); err != nil {
			return nil, ErrSqlNoDatabase
		}
		if fi.IsDir() {
			return nil, ErrSqlNoDatabase
		}
		// open the database file
		return sql.Open("sqlite3", specs[1])
	case "mysql":
		// just connect to the database
		return sql.Open("mysql", specs[1])
	}
	return nil, ErrSqlInvalidDatabaseSpec
}
