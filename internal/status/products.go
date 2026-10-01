// Package status implements read-only registry, signed-index and security-fix comparisons.
package status

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"

	"go.yaml.in/yaml/v3"
	"lupetto/internal/wolfi"
)

const MaxProductsBytes = 1 << 20

var selectorPattern = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)*$`)

type Product struct {
	Package   string   `yaml:"package" json:"package"`
	Selectors []string `yaml:"selectors" json:"selectors"`
}

type Products struct {
	Version  int       `yaml:"version" json:"version"`
	Products []Product `yaml:"products" json:"products"`
}

func LoadProducts(path string) (Products, error) {
	file, err := os.Open(path)
	if err != nil {
		return Products{}, errors.New("cannot open products file")
	}
	defer file.Close()
	return ParseProducts(file)
}

// ParseProducts rejects unknown/duplicate fields, multiple documents, unquoted
// numeric selectors, empty lists, and duplicate package/selector tracks.
func ParseProducts(reader io.Reader) (Products, error) {
	return parseProducts(reader, false)
}

// ParseTrackingProducts uses the same strict format as status, but permits an
// empty products sequence so tracking management can remove the final product.
// Status deliberately continues to require at least one track.
func ParseTrackingProducts(reader io.Reader) (Products, error) {
	return parseProducts(reader, true)
}

func parseProducts(reader io.Reader, allowEmpty bool) (Products, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxProductsBytes+1))
	if err != nil {
		return Products{}, errors.New("cannot read products file")
	}
	if len(data) > MaxProductsBytes {
		return Products{}, errors.New("products file exceeds 1 MiB")
	}
	var node yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&node); err != nil {
		return Products{}, errors.New("invalid products YAML")
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return Products{}, errors.New("products file must contain one YAML document")
	}
	// YAML normally coerces numbers into strings. Selectors are a string-list
	// contract; rejecting that coercion avoids accidental float precision loss.
	if err := checkYAMLTypes(&node); err != nil {
		return Products{}, err
	}
	var products Products
	strict := yaml.NewDecoder(bytes.NewReader(data))
	strict.KnownFields(true)
	if err := strict.Decode(&products); err != nil {
		return Products{}, errors.New("invalid products fields or types")
	}
	if err := validateProducts(products, allowEmpty); err != nil {
		return Products{}, err
	}
	return products, nil
}

func checkYAMLTypes(node *yaml.Node) error {
	if node.Kind == yaml.AliasNode {
		return errors.New("products YAML aliases are not supported")
	}
	if node.Kind == yaml.MappingNode {
		for i := 0; i < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if key.Value == "selectors" && value.Kind == yaml.SequenceNode {
				for _, selector := range value.Content {
					if selector.Kind != yaml.ScalarNode || selector.Tag != "!!str" {
						return errors.New("selectors must be YAML strings")
					}
				}
			}
		}
	}
	for _, child := range node.Content {
		if err := checkYAMLTypes(child); err != nil {
			return err
		}
	}
	return nil
}

func ValidateProducts(products Products) error {
	return validateProducts(products, false)
}

func validateProducts(products Products, allowEmpty bool) error {
	if products.Version != 1 {
		return errors.New("products version must be 1")
	}
	if len(products.Products) == 0 && !allowEmpty {
		return errors.New("products must contain at least one product")
	}
	seen := map[string]bool{}
	for _, product := range products.Products {
		if !wolfi.RequestedNamePattern.MatchString(product.Package) {
			return errors.New("invalid products package or provider name")
		}
		if len(product.Selectors) == 0 {
			return errors.New("each product requires at least one selector")
		}
		for _, selector := range product.Selectors {
			if !selectorPattern.MatchString(selector) {
				return errors.New("products selectors must be dotted numeric strings")
			}
			key := product.Package + "\x00" + selector
			if seen[key] {
				return fmt.Errorf("duplicate product track: %s %s", product.Package, selector)
			}
			seen[key] = true
		}
	}
	return nil
}
