DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'auditlogd_writer') THEN
        CREATE ROLE auditlogd_writer;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'auditlogd_tiering') THEN
        CREATE ROLE auditlogd_tiering;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'auditlogd_api') THEN
        CREATE ROLE auditlogd_api;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'auditor_readonly') THEN
        CREATE ROLE auditor_readonly;
    END IF;
END $$;

-- auditlogd_writer: INSERT on batches, records, worm index; UPDATE on batches
GRANT SELECT, INSERT, UPDATE ON audit_batches TO auditlogd_writer;
GRANT SELECT, INSERT ON audit_records TO auditlogd_writer;
GRANT SELECT, INSERT ON audit_worm_index TO auditlogd_writer;

-- auditlogd_tiering: read records/batches, delete records, insert worm index, update batches
GRANT SELECT, UPDATE ON audit_batches TO auditlogd_tiering;
GRANT SELECT, DELETE ON audit_records TO auditlogd_tiering;
GRANT SELECT, INSERT ON audit_worm_index TO auditlogd_tiering;

-- auditlogd_api: read-only
GRANT SELECT ON audit_batches TO auditlogd_api;
GRANT SELECT ON audit_records TO auditlogd_api;
GRANT SELECT ON audit_worm_index TO auditlogd_api;

-- auditor_readonly: read-only
GRANT SELECT ON audit_batches TO auditor_readonly;
GRANT SELECT ON audit_records TO auditor_readonly;
GRANT SELECT ON audit_worm_index TO auditor_readonly;
