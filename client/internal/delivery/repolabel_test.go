package delivery

import (
	"testing"

	"github.com/leotrace-hq/leoprevent-plugin/client/internal/transcript"
)

func TestAWorkspaceChangeCarriesItsRepoLabel(t *testing.T) {
	// Arrange
	c := transcript.Change{FilePath: "wt10/libs/a.ts", RepoDir: "wt10"}

	// Act
	got := toWire(c)

	// Assert
	if got.RepoLabel != "wt10" || got.Path != "wt10/libs/a.ts" {
		t.Fatalf("got %+v", got)
	}
}
