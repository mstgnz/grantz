-- grantz: authorization schema, MySQL, uuid user ids.
--
-- Four schema files ship with the kit, one per engine and user id type. Run exactly
-- ONE of them, never two: they define the same tables and would collide.
--
--   001_init_postgres.sql        Postgres,      bigint user ids
--   001_init_postgres_uuid.sql   Postgres,      uuid user ids
--   001_init_mysql.sql           MySQL 8.0.19+, bigint user ids
--   001_init_mysql_uuid.sql      MySQL 8.0.19+, char(36) user ids   <- this file
--
-- The four define the same five tables with the same columns in the same order. A
-- test in this repository fails if they drift apart in anything but the type of the
-- user id, because a column added to one and forgotten in another would only ever
-- surface as a runtime SQL error, in whichever project happened to run that file.
--
-- Pair it with the Of forms: grantz.NewOf[uuid.UUID](...) and
-- sqlstore.NewMySQLOf[uuid.UUID](db). MySQL 8.0.19 is the floor, for the row-alias upsert
-- the store's Sync uses.
--
-- char(36) rather than binary(16), because google/uuid's driver.Valuer hands the driver
-- the 36-character text form. A binary column would need a wrapper type on the Go side,
-- and the kit would be dictating how your application spells its ids. A text uuid column
-- and a Go string are the same file again with varchar in place of char.
--
-- Every table is prefixed so the kit can be dropped into a database that already has
-- its own users, roles or permissions tables without colliding.
--
-- The kit deliberately does NOT own users: neither user_id carries a foreign key, because
-- the host application decides what a user is and where it lives. Add the FK yourself if
-- your users table can support it.
--
-- See 001_init_mysql.sql for the full list of what differs from the Postgres schema.

-- ---------------------------------------------------------------------------
-- 1. Permission catalogue.
--
-- Rows here are written by the application at boot (grantz.Sync), not by hand: the list
-- of things the system can do belongs in source control, where a typo fails to compile
-- and a new capability shows up in code review. Only the ROLE MAPPING below is data an
-- administrator edits.
--
-- key is '<resource>.<action>', e.g. 'invoices.cancel'. resource usually matches a table
-- name because that makes keys predictable, but the permission is a business verb, not a
-- table grant: 'invoices.cancel' and 'invoices.update' can be held separately even though
-- both end up writing the same row.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS grantz_permissions (
    `key`       varchar(150) NOT NULL,
    resource    varchar(100) NOT NULL,
    action      varchar(50)  NOT NULL,
    description varchar(500),
    -- Whether field-level restrictions are meaningful for this permission. A 'delete'
    -- or a business verb like 'cancel' has no fields; a 'select' or 'update' does.
    has_fields  boolean      NOT NULL DEFAULT false,
    created_at  datetime     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`key`),
    KEY grantz_permissions_resource_idx (resource)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- 2. Roles.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS grantz_roles (
    id          int          NOT NULL AUTO_INCREMENT,
    `key`       varchar(100) NOT NULL,
    name        varchar(150) NOT NULL,
    description varchar(500),
    active      boolean      NOT NULL DEFAULT true,
    created_at  datetime     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  datetime,
    PRIMARY KEY (id),
    UNIQUE KEY grantz_roles_key_uniq (`key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- 3. Role to permission, with the optional field restriction.
--
-- fields NULL means "every field". A restriction is an allow-list on purpose:
-- {"allow": ["id", "name", "total"]}. With a deny-list, a column added to the table
-- later would leak automatically; with an allow-list it stays hidden until someone
-- decides to expose it. {"allow": ["*"]} is the explicit "all fields" form.
--
-- conditions is reserved and unused today. It is where an attribute rule would go if
-- this ever needs ABAC ("only invoices under 10.000", "not outside working hours").
-- The column exists now so adding that later is a code change, not a migration.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS grantz_role_permissions (
    role_id        int          NOT NULL,
    permission_key varchar(150) NOT NULL,
    fields         json,
    conditions     json,
    created_at     datetime     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (role_id, permission_key),
    KEY grantz_role_permissions_permission_idx (permission_key),
    CONSTRAINT grantz_role_permissions_role_fk
        FOREIGN KEY (role_id) REFERENCES grantz_roles (id) ON DELETE CASCADE,
    CONSTRAINT grantz_role_permissions_permission_fk
        FOREIGN KEY (permission_key) REFERENCES grantz_permissions (`key`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- 4. User to role, with an optional scope.
--
-- scope narrows a role to part of the data: {"company_id": 12}. The kit hands this map
-- back to the caller and does NOT interpret it, because "does this record belong to
-- that scope" is domain knowledge. Keeping the comparison out of the kit is what stops
-- it from growing a query builder.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS grantz_user_roles (
    user_id    char(36) NOT NULL,
    role_id    int      NOT NULL,
    scope      json,
    created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, role_id),
    KEY grantz_user_roles_user_idx (user_id),
    KEY grantz_user_roles_role_idx (role_id),
    CONSTRAINT grantz_user_roles_role_fk
        FOREIGN KEY (role_id) REFERENCES grantz_roles (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- 5. Per-user exception.
--
-- This is the answer to role explosion: when one person needs slightly more or less
-- than their role, you write one row here instead of cloning the role. effect 'deny'
-- always wins over any grant, including one from a role, and that precedence is fixed
-- so nobody has to reason about evaluation order.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS grantz_user_permissions (
    user_id        char(36)     NOT NULL,
    permission_key varchar(150) NOT NULL,
    effect         varchar(10)  NOT NULL,
    fields         json,
    created_at     datetime     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, permission_key),
    KEY grantz_user_permissions_user_idx (user_id),
    KEY grantz_user_permissions_permission_idx (permission_key),
    CONSTRAINT grantz_user_permissions_effect_chk CHECK (effect IN ('allow', 'deny')),
    CONSTRAINT grantz_user_permissions_permission_fk
        FOREIGN KEY (permission_key) REFERENCES grantz_permissions (`key`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
