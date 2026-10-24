package core

import "fmt"

func (s *Service) Bump() int {
	s.count++
	return s.count
}

// Greet moved to its own file.
func (s *Service) Greet() string { return fmt.Sprintf("hi %s", s.name) }
