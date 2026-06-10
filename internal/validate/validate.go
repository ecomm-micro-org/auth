package validate

import (
	"github.com/go-playground/validator/v10"
)

type StructValidator struct {
	Validator *validator.Validate
}

func New() *StructValidator {
	return &StructValidator{
		Validator: validator.New(),
	}
}

func (s *StructValidator) Validate(out any) error {
	return s.Validator.Struct(out)
}
