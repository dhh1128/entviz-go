// Command entviz-conformance is the conformance CLI: read one vector's JSON on
// stdin, write the entviz SVG to stdout (exit 0), or exit non-zero to reject
// (the contract in the entviz repo's compliance/README.md).
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	entviz "github.com/dhh1128/entviz-go"
)

type request struct {
	Entropy string `json:"entropy"`
	Params  struct {
		TargetAR   *float64 `json:"target_ar"`
		FontSizePt *float64 `json:"font_size_pt"`
		Note       *string  `json:"note"`
	} `json:"params"`
}

func main() {
	buf, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "entviz-go: failed to read stdin")
		os.Exit(2)
	}
	var req request
	if err := json.Unmarshal(buf, &req); err != nil {
		fmt.Fprintf(os.Stderr, "entviz-go: invalid request JSON: %v\n", err)
		os.Exit(2)
	}

	targetAR := 1.0
	if req.Params.TargetAR != nil {
		targetAR = *req.Params.TargetAR
	}
	fontSizePt := 12.0
	if req.Params.FontSizePt != nil {
		fontSizePt = *req.Params.FontSizePt
	}

	svg, err := entviz.Render(req.Entropy, targetAR, fontSizePt, req.Params.Note)
	if err != nil {
		fmt.Fprintf(os.Stderr, "entviz-go: rejected: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(svg)
}
