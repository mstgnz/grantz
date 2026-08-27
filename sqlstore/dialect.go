package sqlstore

// A dialect is the SQL this package writes differently per engine, collected in one file
// instead of scattered through the store.
//
// The store's logic is the same everywhere: one union that returns role grants and user
// exceptions together, one upsert, one read of the catalogue. What changes between
// Postgres and MySQL is small and mechanical: how a placeholder is spelled, how an upsert
// is written, whether a NULL needs a cast, and whether "key" has to be quoted. Keeping
// those four in a table makes the difference reviewable; spreading them through the query
// builder is how two engines quietly grow two behaviours.
//
// The type is unexported on purpose. Its fields are raw SQL that decides who may do what,
// so exporting it would either publish a struct nobody outside can fill in, or invite a
// half-written dialect into the permission path. A project on a third engine implements
// grantz.StoreOf directly, which is the two-method interface this package exists to show
// is small.
type dialect struct {
	// name appears in nothing but tests and error messages, and is here so a failure says
	// which engine it came from.
	name string

	// loadGrants must select exactly five columns, in this order:
	// permission_key, effect, fields, scope, from_role. LoadUserGrants scans positionally,
	// so a reordered SELECT in one dialect and not the other is a silent mismatch rather
	// than a compile error. A test pins the order for every dialect.
	loadGrants string

	// userIDArgs is how many times loadGrants wants the user id bound.
	//
	// Postgres numbers its placeholders and reuses $1 for both halves of the union; MySQL
	// has no numbering, so the same value goes in twice. Getting this wrong is not a
	// subtle bug: the driver refuses the query outright.
	userIDArgs int

	// upsertPermission takes key, resource, action, description, has_fields in that order.
	upsertPermission string

	// listPermissionKeys reads the whole catalogue so Sync can report orphans.
	listPermissionKeys string
}

// postgresDialect is the original SQL, unchanged: $1 placeholders, ON CONFLICT, and the
// ::jsonb cast the union needs to type its NULL column.
var postgresDialect = dialect{
	name: "postgres",

	loadGrants: `
SELECT rp.permission_key,
       'allow'   AS effect,
       rp.fields,
       ur.scope,
       true      AS from_role
  FROM grantz_user_roles ur
  JOIN grantz_roles r            ON r.id = ur.role_id AND r.active
  JOIN grantz_role_permissions rp ON rp.role_id = r.id
 WHERE ur.user_id = $1

UNION ALL

SELECT up.permission_key,
       up.effect,
       up.fields,
       NULL::jsonb AS scope,
       false       AS from_role
  FROM grantz_user_permissions up
 WHERE up.user_id = $1`,

	userIDArgs: 1,

	upsertPermission: `
INSERT INTO grantz_permissions (key, resource, action, description, has_fields)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (key) DO UPDATE
   SET resource    = EXCLUDED.resource,
       action      = EXCLUDED.action,
       description = EXCLUDED.description,
       has_fields  = EXCLUDED.has_fields`,

	listPermissionKeys: `SELECT key FROM grantz_permissions`,
}

// mysqlDialect targets MySQL 8.0.19 or later.
//
// The version floor comes from the upsert: the row alias form (VALUES ... AS new) landed
// in 8.0.19 and is the one that is not deprecated. The older VALUES(col) form would reach
// 5.7 and MariaDB, and it is on its way out of MySQL; a permission catalogue is the last
// place to want an upsert that starts warning and then stops parsing.
//
// Three other differences: ? instead of $1 (which is why userIDArgs is 2), a bare NULL
// where Postgres needs ::jsonb, and `key` quoted, because KEY is reserved in MySQL. The
// column is deliberately still called key: the schema reads the same on both engines, and
// the quoting stays a dialect detail rather than leaking into documentation and admin
// tooling.
var mysqlDialect = dialect{
	name: "mysql",

	loadGrants: `
SELECT rp.permission_key,
       'allow'   AS effect,
       rp.fields,
       ur.scope,
       true      AS from_role
  FROM grantz_user_roles ur
  JOIN grantz_roles r            ON r.id = ur.role_id AND r.active
  JOIN grantz_role_permissions rp ON rp.role_id = r.id
 WHERE ur.user_id = ?

UNION ALL

SELECT up.permission_key,
       up.effect,
       up.fields,
       NULL      AS scope,
       false     AS from_role
  FROM grantz_user_permissions up
 WHERE up.user_id = ?`,

	userIDArgs: 2,

	upsertPermission: "\n" + `INSERT INTO grantz_permissions (` + "`key`" + `, resource, action, description, has_fields)
VALUES (?, ?, ?, ?, ?) AS new
ON DUPLICATE KEY UPDATE resource    = new.resource,
                        action      = new.action,
                        description = new.description,
                        has_fields  = new.has_fields`,

	listPermissionKeys: "SELECT `key` FROM grantz_permissions",
}
