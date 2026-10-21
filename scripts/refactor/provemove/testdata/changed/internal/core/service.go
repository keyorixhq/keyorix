package core

// Service is a toy kernel type. (The comment changed: comments never count.)
type Service struct {
	name  string
	count int
}

// NewService builds a Service.
func NewService(name string) *Service { return &Service{name: name} }

var DefaultName = "x"
