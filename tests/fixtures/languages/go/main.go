package main

import (
	"fmt"

	"gopkg.in/yaml.v2"
)

func main() {
	var out map[string]any
	_ = yaml.Unmarshal([]byte("a: 1"), &out)
	fmt.Println(out)
}
