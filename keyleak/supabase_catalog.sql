-- Owner-run metadata export. No application rows or function bodies are read.
BEGIN READ ONLY;
SET LOCAL statement_timeout = '10s';
SET LOCAL search_path = pg_catalog;

WITH audit_schemas AS (
    -- Add every schema exposed by your Data API before exporting.
    SELECT oid, nspname FROM pg_namespace WHERE nspname = ANY (ARRAY['public'])
), client_roles AS (
    SELECT oid, rolname FROM pg_roles WHERE rolname IN ('anon', 'authenticated')
), relations AS (
    SELECT c.oid, c.relowner, c.relacl, n.nspname, c.relname, c.relkind, c.relrowsecurity, c.reloptions
    FROM pg_class c JOIN audit_schemas n ON n.oid = c.relnamespace
    WHERE c.relkind IN ('r', 'p', 'v', 'm')
), functions AS (
    SELECT p.oid, p.proname, p.proargtypes, p.prosecdef, p.proconfig, p.proacl, p.proowner, n.nspname
    FROM pg_proc p JOIN audit_schemas n ON n.oid = p.pronamespace
    WHERE p.prokind = 'f'
)
SELECT jsonb_build_object(
    'version', 1,
    'provider', 'supabase',
    'collected_at', transaction_timestamp(),
    'schemas', (SELECT jsonb_agg(nspname ORDER BY nspname) FROM audit_schemas),
    'relations', COALESCE((SELECT jsonb_agg(jsonb_build_object(
        'schema', c.nspname, 'name', c.relname,
        'kind', CASE c.relkind WHEN 'v' THEN 'view' WHEN 'm' THEN 'materialized_view' ELSE 'table' END,
        'rls_enabled', c.relrowsecurity,
        'security_invoker', COALESCE((SELECT option_value::boolean FROM pg_options_to_table(c.reloptions)
                                     WHERE option_name = 'security_invoker'), false),
        'columns', COALESCE((SELECT jsonb_agg(attname ORDER BY attnum) FROM pg_attribute
                             WHERE attrelid = c.oid AND attnum > 0 AND NOT attisdropped), '[]'::jsonb),
        'write_roles', COALESCE((SELECT jsonb_agg(rolname ORDER BY rolname) FROM (
            SELECT DISTINCT g.rolname FROM (
                SELECT grantee, privilege_type FROM aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner)))
                UNION ALL
                SELECT a.grantee, a.privilege_type FROM pg_attribute col
                CROSS JOIN LATERAL aclexplode(col.attacl) a
                WHERE col.attrelid = c.oid AND col.attnum > 0 AND NOT col.attisdropped
            ) a JOIN pg_roles g ON g.oid = a.grantee
            WHERE a.privilege_type IN ('INSERT', 'UPDATE', 'DELETE')
              AND EXISTS (SELECT FROM client_roles r WHERE pg_has_role(r.oid, g.oid, 'USAGE'))
        ) grant_sources), '[]'::jsonb),
        'destructive_roles', COALESCE((SELECT jsonb_agg(rolname ORDER BY rolname) FROM (
            SELECT DISTINCT g.rolname FROM aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) a
            JOIN pg_roles g ON g.oid = a.grantee
            WHERE a.privilege_type IN ('DELETE', 'TRUNCATE')
              AND EXISTS (SELECT FROM client_roles r WHERE r.rolname = 'anon' AND pg_has_role(r.oid, g.oid, 'USAGE'))
        ) grant_sources), '[]'::jsonb),
        'grants', (SELECT jsonb_object_agg(r.rolname, jsonb_build_object(
            'select', has_table_privilege(r.oid, c.oid, 'SELECT') OR has_any_column_privilege(r.oid, c.oid, 'SELECT'),
            'insert', has_table_privilege(r.oid, c.oid, 'INSERT') OR has_any_column_privilege(r.oid, c.oid, 'INSERT'),
            'update', has_table_privilege(r.oid, c.oid, 'UPDATE') OR has_any_column_privilege(r.oid, c.oid, 'UPDATE'),
            'delete', has_table_privilege(r.oid, c.oid, 'DELETE'),
            'truncate', has_table_privilege(r.oid, c.oid, 'TRUNCATE')
        )) FROM client_roles r)
    ) ORDER BY c.nspname, c.relname) FROM relations c), '[]'::jsonb),
    'functions', COALESCE((SELECT jsonb_agg(jsonb_build_object(
        'schema', p.nspname, 'name', p.proname,
        'identity_arguments', oidvectortypes(p.proargtypes),
        'security_definer', p.prosecdef,
        'execute_roles', COALESCE((SELECT jsonb_agg(rolname ORDER BY rolname) FROM (
            SELECT DISTINCT g.rolname FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a
            JOIN pg_roles g ON g.oid = a.grantee
            WHERE a.privilege_type = 'EXECUTE'
              AND EXISTS (SELECT FROM client_roles r WHERE pg_has_role(r.oid, g.oid, 'USAGE'))
        ) grant_sources), '[]'::jsonb),
        'search_path', (SELECT substring(setting FROM 13) FROM unnest(p.proconfig) AS setting
                        WHERE setting LIKE 'search_path=%' LIMIT 1),
        'execute', (SELECT jsonb_object_agg(r.rolname, has_function_privilege(r.oid, p.oid, 'EXECUTE')) FROM client_roles r)
    ) ORDER BY p.nspname, p.proname, p.oid) FROM functions p), '[]'::jsonb)
);
COMMIT;
