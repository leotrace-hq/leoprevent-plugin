package pathgate

import "testing"

func TestIsMigration_VersionedFilesInMigrationTrees(t *testing.T) {
	for _, p := range []string{
		"supabase/migrations/20261013130832_storage_principal_download_metadata.sql",
		"prisma/migrations/20260921120000_polymorphic_bookings/migration.sql",
		"db/migrate/20260101000000_add_riders.rb",
		"src/main/resources/db/migration/V12__init.sql",
		"db/migrations/001_init.sql",
		"apps/api/migrations/20260915110000_add_driver.ts",
		"migrations/Version20260813140000.php",
		"prisma/migrations/0_init/migration.sql",
		`supabase\migrations\20261013130832_windows.sql`,
	} {
		if !IsMigration(p) {
			t.Errorf("IsMigration(%q) = false", p)
		}
	}
}

func TestIsMigration_KeepsOtherSQLAndSupportCode(t *testing.T) {
	for _, p := range []string{
		"data/dbt/models/reporting/dim_rider.sql",
		"supabase/functions/private/research_claim.sql",
		"supabase/tests/access_codes.sql",
		"prisma/schema.prisma",
		"migrations/helpers.ts",
		"migrations/README.md",
		"src/migrationsService.ts",
		"src/app/features/migration/migration.component.ts",
		"reports/20261013_rider_survey.sql",
		"20261013130832_loose.sql",
		"migration.sql",
	} {
		if IsMigration(p) {
			t.Errorf("IsMigration(%q) = true, want reviewed", p)
		}
	}
}

func TestInertReason_NamesMigrations(t *testing.T) {
	if got := InertReason("supabase/migrations/20261013130832_x.sql"); got != "database migration" {
		t.Errorf("InertReason = %q", got)
	}
}
