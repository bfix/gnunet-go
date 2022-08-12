-- This file is part of gnunet-go, a GNUnet-implementation in Golang.
-- Copyright (C) 2019-2022 Bernd Fix  >Y<
--
-- gnunet-go is free software: you can redistribute it and/or modify it
-- under the terms of the GNU Affero General Public License as published
-- by the Free Software Foundation, either version 3 of the License,
-- or (at your option) any later version.
--
-- gnunet-go is distributed in the hope that it will be useful, but
-- WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
-- Affero General Public License for more details.
--
-- You should have received a copy of the GNU Affero General Public License
-- along with this program.  If not, see <http://www.gnu.org/licenses/>.
--
-- SPDX-License-Identifier: AGPL3.0-or-later

create table meta (
    qkey      blob,         -- key (SHA512 hash)
	btype     integer,      -- block type
	bhash     blob,         -- block hash
    size      integer,      -- size of file
	stored    integer,      -- time added to store
	expires   integer,      -- expiration time
	lastUsed  integer,      -- time last used
	usedCount integer,      -- usage count

	unique(qkey,btype)      -- unique key in database
);
