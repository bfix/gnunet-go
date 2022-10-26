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

create table identities (
    id       integer primary key autoincrement,
    svc      text,
    name     text,
    created  integer,
    modified integer,
    ztype    integer,
    zdata    blob,
    unique (svc,name)
);

create table defaults (
    svc      text unique,
    ident    integer references identities(id)
);

create view v_defaults as select
    i.id as id,
    d.svc as svc,
    i.name as name,
    i.created as created,
    i.modified as modified,
    i.ztype as ztype,
    i.zdata as zdata
from identities i, defaults d
where i.id = d.ident;

create view zones as select
    id, name, created, modified, ztype, zdata
from identities
where svc = 'gns';

create table labels (
    id       integer primary key autoincrement,
    zid      integer references zones(id),
	name     text,
    created  integer,
    modified integer,
    unique (zid,name)
);

create table records (
    id       integer primary key autoincrement,
    lid      integer references labels(id),
    expire   integer,
    created  integer,
    modified integer,
    flags    integer,
    rtype    integer,
    rdata    blob
);
