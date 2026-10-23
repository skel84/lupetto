// Package products owns validated, comment-preserving tracking-file edits.
package products

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"go.yaml.in/yaml/v3"
	"lupetto/internal/status"
	"lupetto/internal/wolfi"
)

var selectorPattern = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)*$`)

// InvalidError distinguishes invalid tracking data from filesystem failures.
type InvalidError struct{ Err error }

func (e *InvalidError) Error() string { return e.Err.Error() }
func invalid(err error) error         { return &InvalidError{Err: err} }

type Document struct {
	Kind     string           `json:"kind"`
	Version  int              `json:"version"`
	Products []status.Product `json:"products"`
	Changed  bool             `json:"changed"`
	Message  string           `json:"message"`
}

func ValidateMutation(action, name string, selectors []string) error {
	if action != "add" && action != "remove" {
		return fmt.Errorf("unknown products action")
	}
	if !wolfi.RequestedNamePattern.MatchString(name) {
		return fmt.Errorf("invalid package or provider name")
	}
	if action == "add" && len(selectors) == 0 {
		return fmt.Errorf("add requires at least one selector")
	}
	for _, selector := range selectors {
		if !selectorPattern.MatchString(selector) {
			return fmt.Errorf("selectors must be dotted numeric strings")
		}
	}
	return nil
}

func Run(path, action, name string, selectors []string, create bool) (Document, error) {
	if action != "list" {
		if err := ValidateMutation(action, name, selectors); err != nil {
			return Document{}, invalid(err)
		}
	}
	var node yaml.Node
	mode := os.FileMode(0600)
	// list only reads, so it follows symlinks (a Kubernetes ConfigMap volume
	// mounts each key as one); add and remove replace the file by atomic
	// rename, which would replace a symlink rather than its target.
	stat := os.Lstat
	if action == "list" {
		stat = os.Stat
	}
	info, err := stat(path)
	if errors.Is(err, os.ErrNotExist) && create && action == "add" {
		if err := yaml.Unmarshal([]byte("version: 1\nproducts: []\n"), &node); err != nil {
			return Document{}, err
		}
	} else {
		if err != nil && action == "add" {
			return Document{}, fmt.Errorf("read products file: %w (use --create with add to create it)", err)
		}
		if err != nil {
			return Document{}, fmt.Errorf("read products file: %w", err)
		}
		if action == "list" && !info.Mode().IsRegular() {
			return Document{}, fmt.Errorf("products file must be a regular file or a symlink to one, not a directory or device")
		}
		if !info.Mode().IsRegular() {
			return Document{}, fmt.Errorf("products file must be a regular file, not a directory or symlink, to be edited")
		}
		mode = info.Mode().Perm()
		file, err := os.Open(path)
		if err != nil {
			return Document{}, fmt.Errorf("read products file: %w", err)
		}
		data, readErr := io.ReadAll(io.LimitReader(file, status.MaxProductsBytes+1))
		closeErr := file.Close()
		if readErr != nil {
			return Document{}, fmt.Errorf("read products file: %w", readErr)
		}
		if closeErr != nil {
			return Document{}, fmt.Errorf("close products file: %w", closeErr)
		}
		if _, err := status.ParseTrackingProducts(bytes.NewReader(data)); err != nil {
			return Document{}, invalid(err)
		}
		if err := yaml.Unmarshal(data, &node); err != nil {
			return Document{}, invalid(err)
		}
	}
	root := node.Content[0]
	sequence := mappingValue(root, "products")
	if sequence == nil || sequence.Kind != yaml.SequenceNode {
		return Document{}, invalid(fmt.Errorf("products must be a YAML sequence"))
	}
	changed := false
	if action == "add" {
		var target *yaml.Node
		existing := map[string]bool{}
		for _, product := range sequence.Content {
			if mappingValue(product, "package").Value != name {
				continue
			}
			values := mappingValue(product, "selectors")
			if target == nil {
				target = values
			}
			for _, value := range values.Content {
				existing[value.Value] = true
			}
		}
		if target == nil {
			target = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle}
			product := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{plainString("package"), plainString(name), plainString("selectors"), target}}
			sequence.Content = append(sequence.Content, product)
		}
		for _, selector := range selectors {
			if !existing[selector] {
				target.Content = append(target.Content, stringNode(selector))
				existing[selector] = true
				changed = true
			}
		}
	} else if action == "remove" {
		wanted := map[string]bool{}
		for _, selector := range selectors {
			wanted[selector] = true
		}
		remaining := make([]*yaml.Node, 0, len(sequence.Content))
		for _, product := range sequence.Content {
			if mappingValue(product, "package").Value != name {
				remaining = append(remaining, product)
				continue
			}
			values := mappingValue(product, "selectors")
			kept := make([]*yaml.Node, 0, len(values.Content))
			for _, value := range values.Content {
				if len(selectors) == 0 || wanted[value.Value] {
					changed = true
				} else {
					kept = append(kept, value)
				}
			}
			values.Content = kept
			if len(kept) != 0 {
				removeUpstream(product, kept)
				remaining = append(remaining, product)
			}
		}
		sequence.Content = remaining
	}
	var buffer bytes.Buffer
	encoder := yaml.NewEncoder(&buffer)
	encoder.SetIndent(2)
	if err := encoder.Encode(&node); err != nil {
		return Document{}, fmt.Errorf("encode products file: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return Document{}, err
	}
	parsed, err := status.ParseTrackingProducts(bytes.NewReader(buffer.Bytes()))
	if err != nil {
		return Document{}, invalid(err)
	}
	if parsed.Products == nil {
		parsed.Products = []status.Product{}
	}
	if changed {
		if info != nil && mode&0222 == 0 {
			return Document{}, fmt.Errorf("products file is read-only")
		}
		if err := atomicReplace(path, buffer.Bytes(), mode); err != nil {
			return Document{}, err
		}
	}
	message := "Tracked products listed"
	if action == "add" {
		message = "Products updated"
		if !changed {
			message = "Already tracked; no changes"
		}
	}
	if action == "remove" {
		message = "Products removed"
		if !changed {
			message = "Not tracked; no changes"
		}
	}
	return Document{Kind: "products", Version: 1, Products: parsed.Products, Changed: changed, Message: message}, nil
}

// removeUpstream drops upstream entries for selectors no longer tracked, and
// the upstream mapping itself once it is empty, so the file stays valid.
func removeUpstream(product *yaml.Node, selectors []*yaml.Node) {
	upstream := mappingValue(product, "upstream")
	if upstream == nil || upstream.Kind != yaml.MappingNode {
		return
	}
	tracked := map[string]bool{}
	for _, selector := range selectors {
		tracked[selector.Value] = true
	}
	kept := make([]*yaml.Node, 0, len(upstream.Content))
	for i := 0; i+1 < len(upstream.Content); i += 2 {
		if tracked[upstream.Content[i].Value] {
			kept = append(kept, upstream.Content[i], upstream.Content[i+1])
		}
	}
	upstream.Content = kept
	if len(kept) != 0 {
		return
	}
	for i := 0; i+1 < len(product.Content); i += 2 {
		if product.Content[i].Value == "upstream" {
			product.Content = append(product.Content[:i], product.Content[i+2:]...)
			return
		}
	}
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}
func plainString(value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
}
func stringNode(value string) *yaml.Node {
	node := plainString(value)
	node.Style = yaml.DoubleQuotedStyle
	return node
}

func atomicReplace(path string, data []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	info, err := os.Stat(directory)
	if err != nil {
		return fmt.Errorf("products directory: %w", err)
	}
	if info.Mode().Perm()&0222 == 0 {
		return fmt.Errorf("products directory is read-only; atomic replacement requires a writable directory")
	}
	file, err := os.CreateTemp(directory, ".lupetto-products-*")
	if err != nil {
		return fmt.Errorf("create products temporary file (directory must be writable): %w", err)
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(mode); err != nil {
		file.Close()
		return fmt.Errorf("preserve products mode: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return fmt.Errorf("write products temporary file: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync products temporary file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close products temporary file: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("replace products file atomically (mount its directory, not a single file): %w", err)
	}
	return nil
}
