// Package status implements read-only registry, signed-index and security-fix comparisons.
package status

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"

	"github.com/distribution/reference"
	"go.yaml.in/yaml/v3"
	"lupetto/internal/imageconfig"
	"lupetto/internal/wolfi"
)

const MaxProductsBytes = 1 << 20

var selectorPattern = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)*$`)

type Product struct {
	Package   string   `yaml:"package" json:"package"`
	Selectors []string `yaml:"selectors" json:"selectors"`
	// Entrypoint is the optional image ENTRYPOINT for every selector of
	// this product; absent means none, as in images built before it existed.
	Entrypoint []string `yaml:"entrypoint,omitempty" json:"entrypoint,omitempty"`
	// CABundle adds the CA certificate bundle to every selector's image.
	CABundle bool `yaml:"caBundle,omitempty" json:"caBundle,omitempty"`
	// Upstream maps a selector to the image reference that selector's Lupetto
	// image replaces. Only the Explorer reads it, to compare vulnerabilities;
	// it does not change what a build produces.
	Upstream map[string]string `yaml:"upstream,omitempty" json:"upstream,omitempty"`
}

// MaxUpstreamReferenceBytes bounds one upstream image reference.
const MaxUpstreamReferenceBytes = 512

// Image returns the image configuration the product's tracks build with.
func (p Product) Image() imageconfig.Options {
	return imageconfig.Options{Entrypoint: p.Entrypoint, CABundle: p.CABundle}
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
			if key.Value == "upstream" {
				if value.Kind != yaml.MappingNode {
					return errors.New("upstream must map quoted selectors to image references")
				}
				for _, element := range value.Content {
					if element.Kind != yaml.ScalarNode || element.Tag != "!!str" {
						return errors.New("upstream selectors and image references must be YAML strings")
					}
				}
			}
			if key.Value == "caBundle" && (value.Kind != yaml.ScalarNode || value.Tag != "!!bool") {
				return errors.New("caBundle must be true or false")
			}
			if key.Value == "entrypoint" {
				if value.Kind != yaml.SequenceNode {
					return errors.New("entrypoint must be a YAML list of strings")
				}
				for _, element := range value.Content {
					if element.Kind != yaml.ScalarNode || element.Tag != "!!str" {
						return errors.New("entrypoint elements must be YAML strings")
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
		if err := product.Image().Validate(); err != nil {
			return fmt.Errorf("invalid products entrypoint for %s: %w", product.Package, err)
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
		if err := validateUpstream(product); err != nil {
			return fmt.Errorf("invalid products upstream for %s: %w", product.Package, err)
		}
	}
	return nil
}

func validateUpstream(product Product) error {
	for selector, ref := range product.Upstream {
		found := false
		for _, candidate := range product.Selectors {
			found = found || candidate == selector
		}
		if !found {
			return fmt.Errorf("selector %q is not one of the product's selectors", selector)
		}
		if err := ValidateUpstreamReference(ref); err != nil {
			return fmt.Errorf("selector %q: %w", selector, err)
		}
	}
	return nil
}

// ValidateUpstreamReference accepts an image reference with a tag or digest,
// for example registry.k8s.io/metrics-server/metrics-server:v0.8.0. A bare
// name is rejected because upstream images are version-specific.
func ValidateUpstreamReference(ref string) error {
	if len(ref) > MaxUpstreamReferenceBytes {
		return fmt.Errorf("image reference exceeds %d bytes", MaxUpstreamReferenceBytes)
	}
	named, err := reference.ParseNormalizedNamed(ref)
	if err != nil {
		return errors.New("not a valid image reference")
	}
	_, tagged := named.(reference.Tagged)
	_, digested := named.(reference.Digested)
	if !tagged && !digested {
		return errors.New("image reference needs a tag or digest")
	}
	return nil
}
