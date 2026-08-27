-- grantz: authorization schema, Postgres, bigint user ids.
--
-- Four schema files ship with the kit, one per engine and user id type. Run exactly
-- ONE of them, never two: they define the same tables and would collide.
--
--   001_init_postgres.sql        Postgres,      bigint user ids   <- this file
--   001_init_postgres_uuid.sql   Postgres,      uuid user ids
--   001_init_mysql.sql           MySQL 8.0.19+, bigint user ids
--   001_init_mysql_uuid.sql      MySQL 8.0.19+, char(36) user ids
--
-- The four define the same five tables with the same columns in the same order. A
-- test in this repository fails if they drift apart in anything but the type of the
-- user id, because a column added to one and forgotten in another would only ever
-- surface as a runtime SQL error, in whichever project happened to run that file.
--
-- Pair it with the unqualified constructors, which are the int64 ones and stay Postgres:
-- grantz.New(...) and sqlstore.New(db).
--
-- Every table is prefixed so the kit can be dropped into a database that already has
-- its own users, roles or permissions tables without colliding.
--
-- The kit deliberately does NOT own users. grantz_user_roles.user_id is a plain bigint
-- with no foreign key, because the host application decides what a user is and where it
-- lives. Add the FK yourself if your users table can support it.

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
    key         varchar(150) PRIMARY KEY,
    resource    varchar(100) NOT NULL,
    action      varchar(50)  NOT NULL,
    description varchar(500),
    -- Whether field-level restrictions are meaningful for this permission. A 'delete'
    -- or a business verb like 'cancel' has no fields; a 'select' or 'update' does.
    has_fields  boolean      NOT NULL DEFAULT false,
    created_at  timestamp    NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS grantz_permissions_resource_idx
    ON grantz_permissions (resource);

-- ---------------------------------------------------------------------------
-- 2. Roles.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS grantz_roles (
    id          serial PRIMARY KEY,
    key         varchar(100) NOT NULL UNIQUE,
    name        varchar(150) NOT NULL,
    description varchar(500),
    active      boolean      NOT NULL DEFAULT true,
    created_at  timestamp    NOT NULL DEFAULT now(),
    updated_at  timestamp
);

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
    role_id        integer      NOT NULL REFERENCES grantz_roles (id) ON DELETE CASCADE,
    permission_key varchar(150) NOT NULL REFERENCES grantz_permissions (key) ON DELETE CASCADE,
    fields         jsonb,
    conditions     jsonb,
    created_at     timestamp    NOT NULL DEFAULT now(),
    PRIMARY KEY (role_id, permission_key)
);

-- ---------------------------------------------------------------------------
-- 4. User to role, with an optional scope.
--
-- scope narrows a role to part of the data: {"company_id": 12}. The kit hands this map
-- back to the caller and does NOT interpret it, because "does this record belong to
-- that scope" is domain knowledge. Keeping the comparison out of the kit is what stops
-- it from growing a query builder.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS grantz_user_roles (
    user_id    bigint    NOT NULL,
    role_id    integer   NOT NULL REFERENCES grantz_roles (id) ON DELETE CASCADE,
    scope      jsonb,
    created_at timestamp NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX IF NOT EXISTS grantz_user_roles_user_idx
    ON grantz_user_roles (user_id);

-- ---------------------------------------------------------------------------
-- 5. Per-user exception.
--
-- This is the answer to role explosion: when one person needs slightly more or less
-- than their role, you write one row here instead of cloning the role. effect 'deny'
-- always wins over any grant, including one from a role, and that precedence is fixed
-- so nobody has to reason about evaluation order.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS grantz_user_permissions (
    user_id        bigint       NOT NULL,
    permission_key varchar(150) NOT NULL REFERENCES grantz_permissions (key) ON DELETE CASCADE,
    effect         varchar(10)  NOT NULL CHECK (effect IN ('allow', 'deny')),
    fields         jsonb,
    created_at     timestamp    NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, permission_key)
);

CREATE INDEX IF NOT EXISTS grantz_user_permissions_user_idx
    ON grantz_user_permissions (user_id);
