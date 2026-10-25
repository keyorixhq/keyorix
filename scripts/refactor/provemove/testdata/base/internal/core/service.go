package core

import "fmt"

// Service is a toy kernel type.
type Service struct {
	name  string
	count int
}

// NewService builds a Service.
func NewService(name string) *Service { return &Service{name: name} }

// Greet says hello.
func (s *Service) Greet() string { return fmt.Sprintf("hi %s", s.name) }

func (s *Service) Bump() int {
	s.count++
	return s.count
}

var defaultName = "x"
