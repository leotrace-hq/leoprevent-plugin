package pathgate

import (
	"regexp"
	"strings"
)

// migrationSegments are the directory names every migration tool writes into: Rails and
// Supabase `migrations/`, Flyway `migration/`, ActiveRecord `db/migrate/`, Prisma
// `prisma/migrations/<timestamp>_name/migration.sql`.
var migrationSegments = map[string]bool{"migrations": true, "migration": true, "migrate": true}

// migrationName is the versioned basename those tools emit: a timestamp or sequence prefix
// (`20261013130832_name.sql`, `001_init.sql`), Flyway's `V12__name.sql`, Doctrine's
// `Version20260813140000.php`, or Prisma's `migration.sql` inside a versioned folder (the
// folder is checked by the caller against prismaFolder, which also admits the `0_init`
// baseline Prisma writes).
var migrationName = regexp.MustCompile(`^(\d{8,14}[_-]|v\d+(\.\d+)*__|\d{3,5}_|version\d{8,})`)

var prismaFolder = regexp.MustCompile(`^\d+_`)

// IsMigration reports a database migration file: a versioned file name INSIDE a migration
// directory. Both halves are required, so a `migrations/helpers.ts` (hand-written support
// code) and a timestamped report outside any migration tree stay reviewable. Measured on
// production (LEO-528): 32 findings on 1,086 migrations over all time, none a real
// vulnerability, for 2.6% of all bytes; the schema-change itself is reviewed once more
// wherever the application reads the data.
func IsMigration(p string) bool {
	q := strings.ReplaceAll(p, `\`, "/")
	segs := strings.Split(q, "/")
	if len(segs) < 2 {
		return false
	}
	base := strings.ToLower(segs[len(segs)-1])
	inTree := false
	for _, s := range segs[:len(segs)-1] {
		if migrationSegments[strings.ToLower(s)] {
			inTree = true
			break
		}
	}
	if !inTree {
		return false
	}
	if migrationName.MatchString(base) {
		return true
	}
	// Prisma: prisma/migrations/20260921120000_polymorphic/migration.sql, and the
	// prisma/migrations/0_init/migration.sql baseline.
	return base == "migration.sql" && prismaFolder.MatchString(segs[len(segs)-2])
}
