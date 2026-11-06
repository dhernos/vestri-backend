package server

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

func TestEndpointAccessRulesAreUnique(t *testing.T) {
	seen := make(map[string]bool)
	for _, rule := range endpointAccess {
		key := rule.Method + " " + rule.Path
		if seen[key] {
			t.Errorf("duplicate access rule: %s", key)
		}
		seen[key] = true
	}
}

func TestRouterRegistrationsAreUnique(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "server.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	methods := map[string]bool{"Get": true, "Post": true, "Put": true, "Patch": true, "Delete": true, "Head": true, "Options": true, "Handle": true}
	seen := make(map[string]bool)
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		method, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !methods[method.Sel.Name] {
			return true
		}
		literal, ok := call.Args[0].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return true
		}
		route, err := strconv.Unquote(literal.Value)
		if err != nil {
			t.Fatal(err)
		}
		key := method.Sel.Name + " " + route
		if seen[key] {
			t.Errorf("duplicate router registration: %s", key)
		}
		seen[key] = true
		return true
	})
}
