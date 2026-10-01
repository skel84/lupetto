package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"lupetto/internal/products"
)

const productsUsage = "\n\nManage tracked products (no network access):\n  lupetto products list --products <file> [--json]\n  lupetto products add <package-or-provider> <selector>... --products <file> [--create] [--json]\n  lupetto products remove <package-or-provider> [<selector>...] --products <file> [--json]\nProducts edits preserve YAML comments where possible and atomically replace the file in its writable directory.\n--create explicitly permits add to create a missing file. Existing pairs are successful no-ops.\nProducts --json prints kind=products, version=1; filesystem errors exit 1 and invalid invocations/data exit 2, without JSON."

type productsRequest struct {
	action, path, name string
	selectors          []string
	json, create       bool
}

func parseProductsCommand(args []string) (productsRequest, error) {
	var request productsRequest
	if len(args) == 0 {
		return request, fmt.Errorf("products requires list, add, or remove")
	}
	request.action = args[0]
	if request.action != "list" && request.action != "add" && request.action != "remove" {
		return request, fmt.Errorf("products requires list, add, or remove")
	}
	var positional []string
	seen := map[string]bool{}
	for i := 1; i < len(args); i++ {
		argument := args[i]
		if strings.HasPrefix(argument, "--") {
			flag, value, equal := strings.Cut(argument, "=")
			if seen[flag] {
				return request, fmt.Errorf("duplicate %s", flag)
			}
			seen[flag] = true
			switch flag {
			case "--json", "--create":
				if equal {
					return request, fmt.Errorf("%s does not accept a value", flag)
				}
				if flag == "--json" {
					request.json = true
				} else {
					request.create = true
				}
			case "--products":
				if !equal {
					i++
					if i >= len(args) || strings.HasPrefix(args[i], "-") {
						return request, fmt.Errorf("--products requires a file")
					}
					value = args[i]
				}
				if strings.TrimSpace(value) == "" {
					return request, fmt.Errorf("--products requires a file")
				}
				request.path = value
			default:
				return request, fmt.Errorf("unknown products flag: %s", flag)
			}
		} else if strings.HasPrefix(argument, "-") {
			return request, fmt.Errorf("unknown products flag: %s", argument)
		} else {
			positional = append(positional, argument)
		}
	}
	if request.path == "" {
		return request, fmt.Errorf("products requires --products <file>")
	}
	if request.create && request.action != "add" {
		return request, fmt.Errorf("--create is only valid with products add")
	}
	if request.action == "list" {
		if len(positional) != 0 {
			return request, fmt.Errorf("products list does not accept package or selectors")
		}
	} else {
		if len(positional) == 0 {
			return request, fmt.Errorf("products %s requires a package", request.action)
		}
		request.name, request.selectors = positional[0], positional[1:]
		if err := products.ValidateMutation(request.action, request.name, request.selectors); err != nil {
			return request, err
		}
	}
	return request, nil
}

func runProducts(args []string, stdout, stderr io.Writer) int {
	request, err := parseProductsCommand(args)
	if err != nil {
		fmt.Fprintf(stderr, "lupetto: %v\n", err)
		return 2
	}
	document, err := products.Run(request.path, request.action, request.name, request.selectors, request.create)
	if err != nil {
		fmt.Fprintf(stderr, "lupetto: %v\n", err)
		var invalid *products.InvalidError
		if errors.As(err, &invalid) {
			return 2
		}
		return 1
	}
	if request.json {
		data, err := json.MarshalIndent(document, "", "  ")
		if err == nil {
			_, err = stdout.Write(append(data, '\n'))
		}
		if err != nil {
			fmt.Fprintf(stderr, "lupetto: write products output: %v\n", err)
			return 1
		}
	} else {
		table := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(table, "PACKAGE\tSELECTORS")
		for _, product := range document.Products {
			fmt.Fprintf(table, "%s\t%s\n", product.Package, strings.Join(product.Selectors, ", "))
		}
		if err := table.Flush(); err != nil {
			fmt.Fprintf(stderr, "lupetto: write products output: %v\n", err)
			return 1
		}
		if _, err := fmt.Fprintln(stdout, document.Message); err != nil {
			fmt.Fprintf(stderr, "lupetto: write products output: %v\n", err)
			return 1
		}
	}
	return 0
}
