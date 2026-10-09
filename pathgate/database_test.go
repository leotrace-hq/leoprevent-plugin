package pathgate

import "testing"

func TestIsDatabaseData_DropsDataDirectoryArtifacts(t *testing.T) {
	// Arrange
	drop := []string{
		"mongo-data/WiredTiger", "mongo-data/WiredTiger.turtle", "mongo-data/WiredTiger.lock",
		"mongo-data/WiredTiger.wt", "mongo-data/WiredTigerHS.wt", "mongo-data/_mdb_catalog.wt",
		"mongo-data/collection-0-8412.wt", "mongo-data/index-1-8412.wt", "dump/app/users.bson",
		"mongo-data/diagnostic.data/metrics.2026-10-08T10-00-00Z-00000",
		"mongo-data/journal/WiredTigerLog.0000000001", "mongo-data/journal/WiredTigerPreplog.0000000002",
		"pgdata/PG_VERSION", "pgdata/postmaster.pid", "pgdata/postmaster.opts", "pgdata/global/pg_control",
		"pgdata/base/16384/1259", "pgdata/base/16384/1259_fsm", "pgdata/base/16384/1259_vm",
		"pgdata/base/16384/24576.1", "pgdata/global/1262", "pgdata/pg_wal/000000010000000000000001",
		"pgdata/pg_xact/0000", "pgdata/pg_multixact/offsets/0000", "pgdata/pg_stat_tmp/global.stat",
		"mysql/ibdata1", "mysql/ibtmp1", "mysql/ib_logfile0", "mysql/#ib_16384_0.dblwr",
		"mysql/#innodb_redo/#ib_redo10", "mysql/#innodb_temp/temp_1.ibt", "mysql/app/users.ibd",
		"mysql/app/users.MYD", "mysql/app/users.MYI", "mysql/binlog.000001", "mysql/mysql-bin.000042",
		"redis/appendonly.aof", "redis/appendonlydir/appendonly.aof.1.incr.aof",
		"app.db-wal", "app.db-shm", "app.db-journal", "dev.sqlite-wal", "dev.sqlite3-shm",
		"data/app.sqlite3-journal", "mssql/data/app.mdf", "mssql/data/app_log.ldf",
		"mssql/data/app_2.ndf", "legacy/app.mdb", "leveldb/000005.ldb",
		`C:\data\db\WiredTiger.wt`, "/var/lib/postgresql/data/pg_wal/000000010000000000000002",
	}

	for _, p := range drop {
		// Act
		got := IsDatabaseData(p)

		// Assert
		if !got {
			t.Errorf("IsDatabaseData(%q) = false, want true", p)
		}
	}
}

func TestIsDatabaseData_KeepsSimilarlyNamedSource(t *testing.T) {
	// Arrange
	keep := []string{
		"app/journal/models.py", "src/database/connection.ts", "db/migrations/001_users.sql",
		"db/seed.sql", "src/wiredtiger_stats.go", "src/pg_wal_reader.py", "scripts/binlog.py",
		"src/binlog_parser.go", "lib/aof.rb", "src/ibdata.ts", "src/postmaster.ts",
		"src/base/handler.py", "src/base/16/handler.py", "web/base/12/34.ts", "src/global/config.go",
		"src/global/404.tsx", "src/db_connect.ts", "app/db.py", "src/sqlite.ts", "src/models/wt.ts",
		"internal/storage/bson.go", "diagnostic/data.go",
		"binlog.go", "mysql-bin.sh", "ib_logfile.py",
	}

	for _, p := range keep {
		// Act
		got := IsDatabaseData(p)

		// Assert
		if got {
			t.Errorf("IsDatabaseData(%q) = true, want false", p)
		}
	}
}

func TestInertReason_NamesDatabaseData(t *testing.T) {
	// Arrange
	p := "mongo-data/collection-0-8412.wt"

	// Act
	got := InertReason(p)

	// Assert
	if got != "database data" {
		t.Errorf("InertReason(%q) = %q, want %q", p, got, "database data")
	}
}

func TestIsGeneratedName_ProtobufDartAndKubernetesCodegen(t *testing.T) {
	// Arrange
	gen := []string{
		"api_pb.js", "api_pb.d.ts", "api_pb.ts", "api_grpc_pb.js", "api_grpc_pb.d.ts",
		"schema_pb2.pyi", "schema_pb2_grpc.pyi", "api.pb.swift", "api.grpc.swift",
		"model.freezed.dart", "repo.mocks.dart", "router.gr.dart",
		"zz_generated.deepcopy.go", "zz_generated.openapi.go",
	}
	keep := []string{
		"pb.js", "api_pbx.js", "webpb.ts", "swift_pb_utils.swift", "freezed.dart",
		"mocks.dart", "gr.dart", "router.dart", "generated_helpers.go", "zz_helpers.go",
	}

	for _, p := range gen {
		// Act
		got := IsGeneratedName(BaseLower(p))

		// Assert
		if !got {
			t.Errorf("IsGeneratedName(%q) = false, want true", p)
		}
	}
	for _, p := range keep {
		// Act
		got := IsGeneratedName(BaseLower(p))

		// Assert
		if got {
			t.Errorf("IsGeneratedName(%q) = true, want false", p)
		}
	}
}
