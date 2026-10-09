package pathgate

import (
	"strings"
)

var databaseBasenames = map[string]bool{
	"wiredtiger": true, "wiredtiger.turtle": true, "wiredtiger.lock": true,
	"pg_version": true, "postmaster.pid": true, "postmaster.opts": true, "pg_control": true,
	"ibdata1": true, "ibtmp1": true,
	"appendonly.aof": true,
}

var databaseNumberedPrefixes = []string{
	"wiredtigerlog.", "wiredtigerpreplog.", "ib_logfile", "mysql-bin.", "binlog.",
}

var databaseExts = map[string]bool{
	".wt": true, ".bson": true, ".ibd": true, ".myd": true, ".myi": true, ".aof": true,
	".mdf": true, ".ndf": true, ".ldf": true, ".mdb": true, ".ldb": true,
	".db-wal": true, ".db-shm": true, ".db-journal": true,
	".sqlite-wal": true, ".sqlite-shm": true, ".sqlite-journal": true,
	".sqlite3-wal": true, ".sqlite3-shm": true, ".sqlite3-journal": true,
}

var databaseSegments = map[string]bool{
	"diagnostic.data": true,
	"pg_wal":          true, "pg_xlog": true, "pg_xact": true, "pg_clog": true, "pg_multixact": true,
	"pg_subtrans": true, "pg_stat_tmp": true, "pg_logical": true, "pg_replslot": true,
	"pg_commit_ts": true, "pg_twophase": true, "pg_snapshots": true, "pg_serial": true,
	"pg_notify": true, "pg_dynshmem": true, "pg_tblspc": true,
	"appendonlydir": true, "#innodb_temp": true, "#innodb_redo": true,
}

func IsDatabaseData(p string) bool {
	q := strings.ReplaceAll(p, `\`, "/")
	segs := strings.Split(q, "/")
	for _, seg := range segs[:len(segs)-1] {
		if databaseSegments[strings.ToLower(seg)] {
			return true
		}
	}
	base := strings.ToLower(segs[len(segs)-1])
	if databaseBasenames[base] {
		return true
	}
	if strings.HasPrefix(base, "#ib_") {
		return true
	}
	for _, pre := range databaseNumberedPrefixes {
		if strings.HasPrefix(base, pre) && allDigits(base[len(pre):]) {
			return true
		}
	}
	if i := strings.LastIndex(base, "."); i >= 0 && databaseExts[base[i:]] {
		return true
	}
	return isPostgresRelation(segs)
}

func isPostgresRelation(segs []string) bool {
	n := len(segs)
	if n >= 3 && segs[n-3] == "base" && allDigits(segs[n-2]) && isRelationFile(segs[n-1]) {
		return true
	}
	return n >= 2 && segs[n-2] == "global" && isRelationFile(segs[n-1])
}

func isRelationFile(name string) bool {
	if i := strings.IndexByte(name, '.'); i >= 0 {
		if !allDigits(name[i+1:]) {
			return false
		}
		name = name[:i]
	}
	for _, fork := range []string{"_fsm", "_vm", "_init"} {
		name = strings.TrimSuffix(name, fork)
	}
	return allDigits(name)
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
