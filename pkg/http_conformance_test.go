package vantage_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHTTPClientConstructionIsCentralised is the guard that makes scope
// enforcement possible.
//
// An embedding consumer wraps its own policy around the Doer it supplies, and
// that guarantee holds only if every request in the library goes through it. A
// check that constructed its own *http.Client would reach straight past the
// guard, and a target the operator never authorised would be contacted anyway.
// Reviewing for that by eye is exactly the kind of vigilance that lapses, so
// it is asserted here instead: the construction is allowed in one file only.
func TestHTTPClientConstructionIsCentralised(t *testing.T) {
	const allowed = "http.go"

	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("locating the module root: %v", err)
	}

	var offenders []string
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// Test files may construct clients freely — they are not the
			// production egress path — but whole directories are still walked
			// so that no package is missed.
			if name := info.Name(); name == ".git" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if filepath.Base(path) == allowed {
			return nil
		}

		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}

		ast.Inspect(f, func(n ast.Node) bool {
			// Matches both &http.Client{...} and http.Client{...}.
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			sel, ok := lit.Type.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Client" {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "http" {
				return true
			}
			rel, _ := filepath.Rel(root, path)
			offenders = append(offenders,
				rel+":"+fset.Position(lit.Pos()).String()[len(path)+1:])
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking the module: %v", err)
	}

	if len(offenders) > 0 {
		t.Fatalf("HTTP clients constructed outside %s, bypassing the egress boundary:\n  %s\n\n"+
			"Route the request through the injected Doer instead, so that an embedding "+
			"consumer's scope guard cannot be circumvented.",
			allowed, strings.Join(offenders, "\n  "))
	}
}
