package main

// This file mechanises the wireproto boundary rule: the upstream modules carrying
// the SPIFFE Workload API and Envoy SDS wire types are imported in exactly one
// package, pkg/wireproto, and everything else reaches those types through its
// aliases. That is what keeps the later replacement of go-control-plane with a
// pruned proto subset an edit of one file instead of a rewrite of every handler.
//
// It is a test rather than a CI grep deliberately. The repository's only workflow is
// gated on the upstream repository name, so it does not run on a fork, and this work
// happens on one. A test runs under plain `go test ./...`, which is what both CI and
// `make test` do, and cannot be skipped by forgetting a step.

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// restrictedModules are the module paths that may only be imported from
// wireprotoDir. Each entry matches the module path itself and every package under
// it, which covers major-version suffixes and submodules.
//
// google.golang.org/grpc and google.golang.org/protobuf are deliberately absent.
// They are not part of the proto swap: a handler names grpc's stream types and
// protobuf's well-known types directly, and those imports survive it untouched.
var restrictedModules = []string{
	"github.com/envoyproxy/go-control-plane",
	"github.com/spiffe/go-spiffe",
}

// wireprotoDir is the one package allowed to import restrictedModules, relative to
// the module root.
//
// The allowance is the directory rather than one filename, so splitting or renaming
// the alias file does not mean editing this test. What stops a rename from silently
// disabling the check is TestWireproto_ImportsEachRestrictedModule below: move the
// aliases out of this directory and the suite fails rather than passing vacuously.
//
// Test files in the directory are allowed too: a test that has to name an alias and
// its upstream target on the same line belongs next to the aliases.
const wireprotoDir = "pkg/wireproto"

// skipDirNames are directories never walked. vendor matters most: CI runs
// `go mod vendor` before `go test`, and the vendored upstream sources would
// otherwise be a wall of false positives.
var skipDirNames = map[string]bool{
	"vendor":   true,
	"testdata": true,
}

func TestRestrictedModules_AreImportedOnlyFromWireproto(t *testing.T) {
	root := moduleRoot(t)

	forEachGoFile(t, root, func(relativePath string, imports []string) {
		if filepath.ToSlash(filepath.Dir(relativePath)) == wireprotoDir {
			return
		}
		for _, imported := range imports {
			if module, restricted := restrictedModuleFor(imported); restricted {
				t.Errorf("%s imports %q: %s may only be imported from %s. "+
					"Add an alias there and use that instead.", relativePath, imported, module, wireprotoDir)
			}
		}
	})
}

// TestWireproto_ImportsEachRestrictedModule keeps the allowance honest. Without it,
// deleting pkg/wireproto or moving its aliases elsewhere would leave a check that
// passes because it has nothing left to find.
func TestWireproto_ImportsEachRestrictedModule(t *testing.T) {
	directory := filepath.Join(moduleRoot(t), filepath.FromSlash(wireprotoDir))
	if _, err := os.Stat(directory); err != nil {
		t.Fatalf("%s does not exist: %v. The handlers reach the upstream wire types through "+
			"its aliases, so it is not optional.", wireprotoDir, err)
	}

	found := map[string]bool{}
	forEachGoFile(t, directory, func(_ string, imports []string) {
		for _, imported := range imports {
			if module, restricted := restrictedModuleFor(imported); restricted {
				found[module] = true
			}
		}
	})

	for _, module := range restrictedModules {
		if !found[module] {
			t.Errorf("no file in %s imports %s, yet it is still on the restricted list. "+
				"Either the aliases moved, which is the bug, or the module is genuinely gone, "+
				"in which case drop it from restrictedModules.", wireprotoDir, module)
		}
	}
}

// restrictedModuleFor reports the restricted module an import path belongs to.
func restrictedModuleFor(importPath string) (string, bool) {
	for _, module := range restrictedModules {
		if importPath == module || strings.HasPrefix(importPath, module+"/") {
			return module, true
		}
	}
	return "", false
}

// forEachGoFile parses every Go file under directory and hands the callback its path
// relative to directory together with its import paths.
//
// Parsing beats grepping on the cases that matter. An aliased, dot or blank import
// all land in the same place, a grouped import block is one node set rather than
// lines to match, and the module path appearing in a comment or a string is not an
// import. Build constraints are ignored on purpose, so a file excluded on this
// platform is still checked.
func forEachGoFile(t *testing.T, directory string, fn func(relativePath string, imports []string)) {
	t.Helper()

	fileSet := token.NewFileSet()
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if path == directory {
				return nil
			}
			name := entry.Name()
			if skipDirNames[name] || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
				return filepath.SkipDir
			}
			// A nested module is not part of this one; hack/tools is the example.
			if _, statErr := os.Stat(filepath.Join(path, "go.mod")); statErr == nil {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), ".go") {
			return nil
		}

		parsed, err := parser.ParseFile(fileSet, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}

		imports := make([]string, 0, len(parsed.Imports))
		for _, spec := range parsed.Imports {
			unquoted, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Errorf("%s: unparsable import path %s: %v", path, spec.Path.Value, err)
				continue
			}
			imports = append(imports, unquoted)
		}

		relativePath, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		fn(relativePath, imports)
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", directory, err)
	}
}

// moduleRoot walks up from the working directory to the directory holding go.mod.
// This file lives in the root package, so that is almost always the working
// directory, and the walk means it keeps working if the file moves.
func moduleRoot(t *testing.T) string {
	t.Helper()

	directory, err := os.Getwd()
	if err != nil {
		t.Fatalf("unable to determine the working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil {
			return directory
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			t.Fatalf("no go.mod found above %s", directory)
		}
		directory = parent
	}
}
