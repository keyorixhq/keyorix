### Changed

- The egress inventory guard (`TestEgressEveryDirectDependencyIsClassified`) now derives a module's direct dependencies from the imports of its Go files, test files included, instead of the `// indirect` markers of `go.mod`, so a `go mod tidy` (a Dependabot PR) can no longer turn a green guard on main red. Its failure message names the dependency, the importing file and where to add the classification row.
