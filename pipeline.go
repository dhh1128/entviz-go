package entviz

// Full render pipeline: entropy string -> SVG string (spec v10).
//
// Faithful port of entviz-rs/src/pipeline.rs (itself a port of pipeline.py +
// renderer.py + shapes.py). Produces an SVG whose normative data-* attributes
// and geometry let the conformance Tier-A extractor recover the golden render
// model, and whose non-text pixels match the golden Tier-B raster.

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	dpi                 = 96.0
	noteMaxLen          = 10
	maxInputChars       = 65536
	monospaceFontFamily = "\"JetBrains Mono\", \"Menlo\", \"Consolas\", \"DejaVu Sans Mono\", \"Liberation Mono\", \"Roboto Mono\", \"Noto Sans Mono\", monospace"
)

// RenderError represents a render rejection. Kind discriminates the reason.
type RenderError struct {
	Kind     string // "note" | "input-too-long" | "font-size" | "aspect-ratio" | "no-tokens" | "eip55"
	Message  string
	Position int // for eip55
}

func (e *RenderError) Error() string {
	if e.Kind == "eip55" {
		return fmt.Sprintf("EIP-55 checksum mismatch at position %d", e.Position)
	}
	return e.Message
}

func sanitizeNote(note *string) (*string, error) {
	if note == nil {
		return nil, nil
	}
	n := *note
	if n == "" {
		return nil, nil
	}
	count := utf8.RuneCountInString(n)
	if count > noteMaxLen {
		return nil, &RenderError{
			Kind:    "note",
			Message: fmt.Sprintf("note must be at most %d characters (got %d)", noteMaxLen, count),
		}
	}
	for _, c := range n {
		if c < ' ' || c > '~' {
			return nil, &RenderError{
				Kind:    "note",
				Message: "note must be printable ASCII (U+0020-U+007E); no control or non-ASCII characters",
			}
		}
	}
	return &n, nil
}

// ---- tiny XML helpers ----

var (
	attrEscaper = strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
	)
	textEscaper = strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
	)
)

func escAttr(s string) string {
	return attrEscaper.Replace(s)
}

func escText(s string) string {
	return textEscaper.Replace(s)
}

// n serializes a coordinate per the spec's numeric rule: a finite plain
// decimal, never exponential, <=3 fractional digits, no trailing zeros,
// integers without a decimal point, -0 as 0. Rounding is half-to-even.
func n(x float64) string {
	if math.IsInf(x, 0) || math.IsNaN(x) {
		return "0"
	}
	s := strconv.FormatFloat(roundHalfEven(x, 3), 'f', -1, 64)
	if s == "-0" || s == "" {
		s = "0"
	}
	return s
}

// roundHalfEven rounds x to the given number of decimal places using
// round-half-to-even (banker's rounding), matching Rust's {:.3} formatter.
func roundHalfEven(x float64, places int) float64 {
	pow := math.Pow(10, float64(places))
	return math.RoundToEven(x*pow) / pow
}

// Render renders entropy as an entviz SVG string.
func Render(entropyText string, targetAR, fontSizePt float64, note *string) (string, error) {
	sanitized, err := sanitizeNote(note)
	if err != nil {
		return "", err
	}
	if utf8.RuneCountInString(entropyText) > maxInputChars {
		return "", &RenderError{Kind: "input-too-long", Message: "input too long"}
	}
	if fontSizePt < 6.0 || fontSizePt > 30.0 {
		return "", &RenderError{Kind: "font-size", Message: "font size out of range"}
	}
	if targetAR < 0.01 || targetAR > 100.0 {
		return "", &RenderError{Kind: "aspect-ratio", Message: "aspect ratio out of range"}
	}

	rawInput := strings.TrimSpace(entropyText)
	parsed, perr := Parse(rawInput)
	if perr != nil {
		if e, ok := perr.(*Eip55Error); ok {
			return "", &RenderError{Kind: "eip55", Position: e.Position}
		}
		return "", perr
	}

	var core, typeName string
	var alphabet Alphabet
	var prefix, suffix *string
	prefixSemantic := false

	if parsed == nil {
		core = b64urlEncode([]byte(rawInput))
		typeName = fmt.Sprintf("txt(%d)->b64url", utf8.RuneCountInString(rawInput))
		alphabet = BASE64URL
	} else {
		core = parsed.Core
		typeName = parsed.TypeName
		alphabet = parsed.Alphabet
		prefix = parsed.Prefix
		suffix = parsed.Suffix
		prefixSemantic = parsed.PrefixSemantic
		switch typeName {
		case "hex":
			typeName = fmt.Sprintf("hex(%d)", utf8.RuneCountInString(core))
		case "base64":
			typeName = fmt.Sprintf("b64(%d)", utf8.RuneCountInString(core))
		case "base64url":
			typeName = fmt.Sprintf("b64url(%d)", utf8.RuneCountInString(core))
		}
	}

	tokens, isTruncated := TokenizeEntropy(core, alphabet)
	if len(tokens) == 0 {
		return "", &RenderError{Kind: "no-tokens", Message: "no tokens"}
	}
	truncatedBytes := -1
	if isTruncated {
		truncatedBytes = len(rawInput)
	}
	tokenCount := len(tokens)

	fingerprintCore := core
	if prefix != nil && prefixSemantic {
		fingerprintCore = *prefix + core
	}

	primary := ComputeFingerprint(fingerprintCore)
	ftoksAll := TokenizeFingerprint(primary)
	usedFtoks := make([]Token, tokenCount)
	copy(usedFtoks, ftoksAll[:tokenCount])

	gridTokenCount := tokenCount
	if isTruncated {
		gridTokenCount = 22
	}
	grid := ChooseGrid(gridTokenCount, targetAR)
	medianFtok, _ := MedianToken(usedFtoks)
	quartileFtoks := QuartileTokens(usedFtoks)
	style := SelectVisualStyle(medianFtok)

	cellIndices := assignCellIndices(tokens, grid, &medianFtok, usedFtoks)

	// --- geometry ---
	fontPx := fontSizePt * dpi / 72.0
	nucleusW := fontPx * 3.0
	nucleusH := fontPx * 1.25
	boxW := nucleusW / 8.0
	boxH := nucleusH / 2.0
	cellW := nucleusW + 2.0*boxW
	cellH := nucleusH + 2.0*boxH
	gm := boxH / 2.0
	barW := 2.0 * boxH
	gridW := cellW * float64(grid.Cols)
	gridH := cellH * float64(grid.Rows)

	boundingW := 1.0 + barW + 1.0 + gm + gridW + gm + 1.0
	hasBottomLabel := suffix != nil || sanitized != nil
	bottomRegion := gm
	if hasBottomLabel {
		bottomRegion = nucleusH + gm
	}
	boundingH := 1.0 + gm + nucleusH + gridH + bottomRegion + 1.0

	gridLeft := 1.0 + barW + 1.0 + gm
	gridTop := 1.0 + gm + nucleusH
	gridRight := gridLeft + gridW
	gridBottom := gridTop + gridH

	cellCount := grid.Cols * grid.Rows
	usedCells := map[int]bool{}
	for _, ci := range cellIndices {
		usedCells[ci] = true
	}

	// --- per-cell text sizes ---
	var cellTextPt float64
	if alphabet.BitsPerChar == 4 {
		cellTextPt = math.RoundToEven(fontSizePt * 0.75)
	} else {
		cellTextPt = fontSizePt
	}
	cellTextPx := cellTextPt * dpi / 72.0
	labelTextPx := math.RoundToEven(fontSizePt*0.75) * dpi / 72.0
	fpMiddleTextPx := math.RoundToEven(fontSizePt*0.80) * dpi / 72.0

	// --- fingerprint-edge cells (v10) ---
	fpEdgeCells := map[int]bool{}
	if usedCells[0] {
		fpEdgeCells[0] = true
	}
	for qi := 0; qi < 2 && qi < len(quartileFtoks); qi++ {
		q := quartileFtoks[qi]
		if q != nil {
			fpEdgeCells[cellIndices[q.Index]] = true
		}
	}

	// --- nucleus bg per token ---
	type tokenCell struct {
		token     *Token
		ftok      *Token
		ci        int
		nucleusBg string
	}
	tokenCells := make([]tokenCell, 0, tokenCount)
	for i := range tokens {
		token := &tokens[i]
		ci := cellIndices[token.Index]
		var nucleusBg string
		if isTruncated && token.Index >= 8 && token.Index <= 11 {
			nucleusBg = style.BgColor
		} else {
			bg, _ := NucleusColors(token.Quant)
			nucleusBg = bg
		}
		tokenCells = append(tokenCells, tokenCell{token, &usedFtoks[token.Index], ci, nucleusBg})
	}

	// ===================== build SVG =====================
	var s strings.Builder
	s.Grow(8192)

	truncAttr := ""
	if isTruncated {
		truncAttr = " data-truncated=\"true\""
	}
	s.WriteString(fmt.Sprintf(
		"<svg width=\"%s\" height=\"%s\" viewBox=\"0 0 %s %s\" xmlns=\"http://www.w3.org/2000/svg\" "+
			"font-family=\"%s\" "+
			"data-entviz-version=\"%s\" data-entviz-lib=\"%s\" data-input-bytes=\"%d\" "+
			"data-cols=\"%d\" data-rows=\"%d\"%s>",
		n(boundingW), n(boundingH), n(boundingW), n(boundingH),
		escAttr(monospaceFontFamily),
		SpecVersion, LibVersion, len(rawInput),
		grid.Cols, grid.Rows, truncAttr,
	))

	// defs + clipPath
	var digestHexB strings.Builder
	for _, b := range primary[:8] {
		fmt.Fprintf(&digestHexB, "%02x", b)
	}
	clipID := fmt.Sprintf("grid-clip-%s-%dx%d", digestHexB.String(), grid.Cols, grid.Rows)
	s.WriteString(fmt.Sprintf(
		"<defs><clipPath id=\"%s\"><rect x=\"%s\" y=\"%s\" width=\"%s\" height=\"%s\"/></clipPath></defs>",
		escAttr(clipID), n(gridLeft), n(gridTop), n(gridW), n(gridH),
	))

	// bounding white background
	s.WriteString(fmt.Sprintf(
		"<rect x=\"0\" y=\"0\" width=\"%s\" height=\"%s\" fill=\"#ffffff\"/>",
		n(boundingW), n(boundingH),
	))

	// grid channel
	s.WriteString("<g data-channel=\"grid\">")
	s.WriteString(fmt.Sprintf(
		"<rect x=\"%s\" y=\"%s\" width=\"%s\" height=\"%s\" fill=\"%s\"/>",
		n(gridLeft), n(gridTop), n(gridW), n(gridH), escAttr(style.BgColor),
	))

	// Layer 1: surround edges.
	type surroundInfo struct {
		bits      uint32
		edgeColor string
	}
	surroundByCell := map[int]surroundInfo{}
	s.WriteString("<g>")
	for _, tc := range tokenCells {
		ftok := tc.ftok
		ci := tc.ci
		var edgeColor string
		if fpEdgeCells[ci] {
			edgeColor = style.EdgeColors[ftok.Quant&0b11]
		} else {
			edgeColor = ClosestPaletteColor(tc.nucleusBg, style.EdgeColors)
		}
		col := ci % grid.Cols
		row := ci / grid.Cols
		cellLeft := gridLeft + float64(col)*cellW
		cellTop := gridTop + float64(row)*cellH
		var bits uint32
		var d strings.Builder
		for i := uint32(0); i < 24; i++ {
			if (ftok.Quant>>i)&1 == 0 {
				continue
			}
			bits |= 1 << i
			ox, oy := boxOrigin(i, cellLeft, cellTop, boxW, boxH)
			d.WriteString(fmt.Sprintf("M%s %sh%sv%sh-%sz", n(ox), n(oy), n(boxW), n(boxH), n(boxW)))
		}
		if d.Len() > 0 {
			s.WriteString(fmt.Sprintf("<path fill=\"%s\" d=\"%s\"/>", escAttr(edgeColor), d.String()))
		}
		surroundByCell[ci] = surroundInfo{bits, edgeColor}
	}
	s.WriteString("</g>")

	// Layer 2: ellipse overlay (appended inside grid channel)
	drawEllipseOverlay(&s, &primary, grid, gridLeft, gridTop, gridW, gridH, cellW, cellH, style.BgColor, clipID)

	// --- min/max ftok cells for the blank map ---
	minCellQ := uint32(math.MaxUint32)
	minCellIdx := 0
	maxCellQ := uint32(0)
	maxCellIdx := 0
	for i := range tokens {
		token := &tokens[i]
		q := usedFtoks[token.Index].Quant
		ci := cellIndices[token.Index]
		if q < minCellQ || (q == minCellQ && ci > minCellIdx) {
			minCellQ = q
			minCellIdx = ci
		}
		if q > maxCellQ || (q == maxCellQ && ci > maxCellIdx) {
			maxCellQ = q
			maxCellIdx = ci
		}
	}

	// --- blanks + fills ---
	var blankIndices []int
	for ci := 0; ci < cellCount; ci++ {
		if !usedCells[ci] {
			blankIndices = append(blankIndices, ci)
		}
	}
	mapCellIdx := -1
	if len(blankIndices) > 0 {
		mapCellIdx = blankIndices[0]
		for _, bi := range blankIndices {
			if bi < mapCellIdx {
				mapCellIdx = bi
			}
		}
	}
	soleBlank := len(blankIndices) == 1
	mapFill := "#ffffff"
	if style.BgColor == "#ffffff" {
		mapFill = "#e7be00"
	}
	blankFillColor := map[int]string{}
	j := 0
	for _, bi := range blankIndices {
		if bi != mapCellIdx || soleBlank {
			color := style.EdgeColors[primary[32+j]&0b11]
			blankFillColor[bi] = color
			j++
		}
	}

	// --- quartile marks per cell ---
	tokenByIndex := map[int]*Token{}
	for i := range tokens {
		tokenByIndex[tokens[i].Index] = &tokens[i]
	}
	type quartileInfo struct {
		qIdx int
		fg   string
	}
	quartileOfCell := map[int]quartileInfo{}
	for qIdx, qFtok := range quartileFtoks {
		if qFtok != nil {
			ci := cellIndices[qFtok.Index]
			if token, ok := tokenByIndex[qFtok.Index]; ok {
				_, fg := NucleusColors(token.Quant)
				quartileOfCell[ci] = quartileInfo{qIdx, fg}
			}
		}
	}

	// fingerprint cells (token indices 8..11) for tagging
	fingerprintCells := map[int]bool{}
	if isTruncated {
		for t := 8; t < 12; t++ {
			fingerprintCells[cellIndices[t]] = true
		}
	}

	// Layer 3+: per-cell groups in cell-index order
	s.WriteString("<g>")
	fpBorder := "#ffffff"
	if style.BgColor == "#ffffff" {
		fpBorder = "#e7be00"
	}
	cornerRadius := nucleusH / 2.0
	for ci := 0; ci < cellCount; ci++ {
		col := ci % grid.Cols
		row := ci / grid.Cols
		var attrs strings.Builder
		attrs.WriteString(fmt.Sprintf(
			" data-channel=\"cell\" data-cell-index=\"%d\" data-cell-row=\"%d\" data-cell-col=\"%d\"",
			ci, row, col,
		))
		isBlank := !usedCells[ci]
		if isBlank {
			attrs.WriteString(" data-cell-blank=\"true\"")
		}
		if fingerprintCells[ci] {
			attrs.WriteString(" data-cell-fingerprint=\"true\"")
		}
		isMap := isBlank && ci == mapCellIdx
		if isMap {
			attrs.WriteString(" data-cell-blank-map=\"true\"")
		}
		if qi, ok := quartileOfCell[ci]; ok {
			attrs.WriteString(fmt.Sprintf(" data-cell-quartile=\"%d\"", qi.qIdx+1))
		}
		if si, ok := surroundByCell[ci]; ok {
			attrs.WriteString(fmt.Sprintf(" data-surround-bits=\"0x%x\"", si.bits))
			if si.bits != 0 {
				attrs.WriteString(fmt.Sprintf(" data-edge-color=\"%s\"", escAttr(si.edgeColor)))
			}
		}
		s.WriteString("<g" + attrs.String() + ">")

		if isBlank {
			nx := gridLeft + float64(col)*cellW + boxW
			ny := gridTop + float64(row)*cellH + boxH
			var blankFill string
			if isMap && !soleBlank {
				blankFill = mapFill
			} else {
				blankFill = blankFillColor[ci]
			}
			s.WriteString(fmt.Sprintf(
				"<rect x=\"%s\" y=\"%s\" width=\"%s\" height=\"%s\" rx=\"%s\" ry=\"%s\" fill=\"%s\" stroke=\"#000000\" stroke-width=\"1\"/>",
				n(nx), n(ny), n(nucleusW), n(nucleusH), n(cornerRadius), n(cornerRadius), escAttr(blankFill),
			))
			if isMap {
				subW := nucleusW / float64(grid.Cols)
				subH := nucleusH / float64(grid.Rows)
				dotR := nucleusH/8.0 + fontPx/16.0
				maxCx, maxCy := subCenter(maxCellIdx, nx, ny, grid, subW, subH)
				minCx, minCy := subCenter(minCellIdx, nx, ny, grid, subW, subH)
				maxRow, maxCol := maxCellIdx/grid.Cols, maxCellIdx%grid.Cols
				minRow, minCol := minCellIdx/grid.Cols, minCellIdx%grid.Cols
				plusArm := dotR * 1.2
				plusW := math.Max(dotR*0.55, 1.0)
				var minColor, maxColor string
				if soleBlank {
					f := blankFillColor[mapCellIdx]
					quant := parseHexByte(f[1:3]) | (parseHexByte(f[3:5]) << 8) | (parseHexByte(f[5:7]) << 16)
					_, mc := NucleusColors(uint32(quant))
					minColor, maxColor = mc, mc
				} else {
					minColor, maxColor = "#1d4ed8", "#d62828"
				}
				s.WriteString(fmt.Sprintf(
					"<circle cx=\"%s\" cy=\"%s\" r=\"%s\" fill=\"%s\" data-blank-map-min=\"%d,%d\"/>",
					n(minCx), n(minCy), n(dotR), escAttr(minColor), minRow, minCol,
				))
				s.WriteString(fmt.Sprintf(
					"<path d=\"M %s,%s H %s M %s,%s V %s\" fill=\"none\" stroke=\"%s\" stroke-width=\"%s\" stroke-linecap=\"butt\" data-blank-map-max=\"%d,%d\"/>",
					n(maxCx-plusArm), n(maxCy), n(maxCx+plusArm),
					n(maxCx), n(maxCy-plusArm), n(maxCy+plusArm),
					escAttr(maxColor), n(plusW), maxRow, maxCol,
				))
			}
		} else {
			var tc *tokenCell
			for i := range tokenCells {
				if tokenCells[i].ci == ci {
					tc = &tokenCells[i]
					break
				}
			}
			token := tc.token
			isFpMiddle := isTruncated && token.Index >= 8 && token.Index <= 11
			r := uint32(parseHexByte(tc.nucleusBg[1:3]))
			g := uint32(parseHexByte(tc.nucleusBg[3:5]))
			b := uint32(parseHexByte(tc.nucleusBg[5:7]))
			bgColor, fgColor := NucleusColors(r | (g << 8) | (b << 16))
			nx := gridLeft + float64(col)*cellW + boxW
			ny := gridTop + float64(row)*cellH + boxH
			s.WriteString(fmt.Sprintf(
				"<rect x=\"%s\" y=\"%s\" width=\"%s\" height=\"%s\" fill=\"%s\"/>",
				n(nx), n(ny), n(nucleusW), n(nucleusH), escAttr(bgColor),
			))
			if isFpMiddle {
				s.WriteString(fmt.Sprintf(
					"<rect x=\"%s\" y=\"%s\" width=\"%s\" height=\"%s\" fill=\"none\" stroke=\"%s\" stroke-width=\"1\"/>",
					n(nx+0.5), n(ny+0.5), n(nucleusW-1.0), n(nucleusH-1.0), escAttr(fpBorder),
				))
			}
			textPx := cellTextPx
			if isFpMiddle {
				textPx = fpMiddleTextPx
			}
			cx := nx + nucleusW/2.0
			cy := ny + nucleusH/2.0
			s.WriteString(fmt.Sprintf(
				"<text x=\"%s\" y=\"%s\" fill=\"%s\" font-size=\"%s\" text-anchor=\"middle\" dominant-baseline=\"central\">%s</text>",
				n(cx), n(cy), escAttr(fgColor), n(textPx), escText(token.Text),
			))
			if qi, ok := quartileOfCell[ci]; ok {
				poly := quartilePolygon(qi.qIdx, nx, ny, nucleusW, nucleusH)
				s.WriteString(fmt.Sprintf("<polygon points=\"%s\" fill=\"%s\"/>", poly, escAttr(qi.fg)))
			}
		}
		s.WriteString("</g>")
	}
	s.WriteString("</g>") // nuclei group
	s.WriteString("</g>") // grid channel

	// color bar
	second := SecondDigest(core)
	drawColorBar(&s, &primary, &second, style, barW, boundingH, cellTextPx)

	// labels
	drawLabelStrips(&s, gridLeft, gridRight, gridTop, gridBottom, nucleusH,
		typeName, prefix, suffix, labelTextPx, truncatedBytes, sanitized)

	// borders
	bl := func(x1, y1, x2, y2 float64) {
		s.WriteString(fmt.Sprintf(
			"<line x1=\"%s\" y1=\"%s\" x2=\"%s\" y2=\"%s\" stroke=\"#808080\" stroke-width=\"1\" shape-rendering=\"crispEdges\"/>",
			n(x1), n(y1), n(x2), n(y2),
		))
	}
	bl(0.0, 0.5, boundingW, 0.5)
	bl(boundingW-0.5, 0.0, boundingW-0.5, boundingH)
	bl(0.0, boundingH-0.5, boundingW, boundingH-0.5)
	bl(0.5, 0.0, 0.5, boundingH)
	bl(1.0+barW+0.5, 0.0, 1.0+barW+0.5, boundingH)

	s.WriteString("</svg>")
	return s.String(), nil
}

func boxOrigin(i uint32, cellLeft, cellTop, bw, bh float64) (float64, float64) {
	switch {
	case i < 10:
		return cellLeft + float64(i)*bw, cellTop
	case i < 12:
		return cellLeft + 9.0*bw, cellTop + bh + float64(i-10)*bh
	case i < 22:
		return cellLeft + float64(21-i)*bw, cellTop + 3.0*bh
	default:
		return cellLeft, cellTop + bh + float64(23-i)*bh
	}
}

func subCenter(cellIdx int, nx, ny float64, grid Grid, subW, subH float64) (float64, float64) {
	return nx + float64(cellIdx%grid.Cols)*subW + 0.5*subW,
		ny + float64(cellIdx/grid.Cols)*subH + 0.5*subH
}

func quartilePolygon(qIdx int, nx, ny, w, h float64) string {
	leg := h / 2.0
	left, top, right, bottom := nx, ny, nx+w, ny+h
	var pts [3][2]float64
	switch qIdx {
	case 0:
		pts = [3][2]float64{{left, top}, {left + leg, top}, {left, top + leg}}
	case 1:
		pts = [3][2]float64{{right, top}, {right - leg, top}, {right, top + leg}}
	case 2:
		pts = [3][2]float64{{right, bottom}, {right, bottom - leg}, {right - leg, bottom}}
	default:
		pts = [3][2]float64{{left, bottom}, {left, bottom - leg}, {left + leg, bottom}}
	}
	parts := make([]string, 3)
	for i, p := range pts {
		parts[i] = n(p[0]) + "," + n(p[1])
	}
	return strings.Join(parts, " ")
}

// --- ellipse overlay ---

func drawEllipseOverlay(s *strings.Builder, digest *[64]byte, grid Grid,
	gridLeft, gridTop, gridW, gridH, cellW, cellH float64, bgColor, clipID string) {
	interiorCount := saturatingSub(grid.Cols, 1) * saturatingSub(grid.Rows, 1)
	var points [][2]float64
	if interiorCount >= 6 {
		for r := 1; r < grid.Rows; r++ {
			for c := 1; c < grid.Cols; c++ {
				points = append(points, [2]float64{gridLeft + float64(c)*cellW, gridTop + float64(r)*cellH})
			}
		}
	} else {
		for c := 0; c <= grid.Cols; c++ {
			points = append(points, [2]float64{gridLeft + float64(c)*cellW, gridTop})
		}
		for r := 1; r < grid.Rows; r++ {
			points = append(points, [2]float64{gridLeft, gridTop + float64(r)*cellH})
			points = append(points, [2]float64{gridLeft + float64(grid.Cols)*cellW, gridTop + float64(r)*cellH})
		}
		for c := 0; c <= grid.Cols; c++ {
			points = append(points, [2]float64{gridLeft + float64(c)*cellW, gridTop + float64(grid.Rows)*cellH})
		}
	}
	if len(points) == 0 {
		return
	}
	anchor := points[int(digest[60])%len(points)]
	gridRight := gridLeft + gridW
	gridBottom := gridTop + gridH
	corners := [4][2]float64{
		{gridLeft, gridTop}, {gridRight, gridTop}, {gridLeft, gridBottom}, {gridRight, gridBottom},
	}
	dFar := 0.0
	for _, c := range corners {
		d := math.Sqrt(math.Pow(c[0]-anchor[0], 2) + math.Pow(c[1]-anchor[1], 2))
		if d > dFar {
			dFar = d
		}
	}
	rMin := 0.22 * dFar
	rMax := 0.58 * dFar
	if rMax <= rMin {
		return
	}
	rx := rMin + (float64(digest[61]%16)/15.0)*(rMax-rMin)
	ry := rMin + (float64(digest[62]%16)/15.0)*(rMax-rMin)
	rotation := (float64(digest[63]%16) / 15.0) * 180.0
	fill, fillOp, edgeOp := overlayForBg(bgColor)
	strokeW := cellH / 20.0
	s.WriteString(fmt.Sprintf(
		"<g clip-path=\"url(#%s)\" data-channel=\"ellipse\" data-ellipse-anchor-x=\"%s\" data-ellipse-anchor-y=\"%s\" data-ellipse-rx=\"%s\" data-ellipse-ry=\"%s\" data-ellipse-rotation-deg=\"%s\">",
		escAttr(clipID), n(anchor[0]), n(anchor[1]), n(rx), n(ry), n(rotation),
	))
	s.WriteString(fmt.Sprintf(
		"<ellipse cx=\"%s\" cy=\"%s\" rx=\"%s\" ry=\"%s\" transform=\"rotate(%s %s %s)\" fill=\"%s\" stroke=\"%s\" fill-opacity=\"%s\" stroke-opacity=\"%s\" stroke-width=\"%s\"/>",
		n(anchor[0]), n(anchor[1]), n(rx), n(ry), n(rotation), n(anchor[0]), n(anchor[1]),
		fill, fill, n(fillOp), n(edgeOp), n(strokeW),
	))
	s.WriteString("</g>")
}

func saturatingSub(a, b int) int {
	if a < b {
		return 0
	}
	return a - b
}

func overlayForBg(bg string) (string, float64, float64) {
	switch bg {
	case "#ffffff":
		return "#000000", 0.20, 0.30
	case "#e7be00":
		return "#000000", 0.20, 0.30
	case "#ff3f2f":
		return "#000000", 0.25, 0.35
	case "#2f3fbf":
		return "#ffffff", 0.35, 0.45
	default:
		return "#000000", 0.20, 0.30
	}
}

// --- color bar ---

func firstAppearance(digest *[64]byte) [4]int {
	first := [4]int{-1, -1, -1, -1}
	idx := 0
	for _, b := range digest {
		for _, shift := range [4]uint{0, 2, 4, 6} {
			p := int((b >> shift) & 3)
			if first[p] == -1 {
				first[p] = idx
			}
			idx++
		}
	}
	order := [4]int{0, 1, 2, 3}
	sort.SliceStable(order[:], func(a, b int) bool {
		pa, pb := order[a], order[b]
		if first[pa] != first[pb] {
			return first[pa] < first[pb]
		}
		return pa < pb
	})
	return order
}

func drawColorBar(s *strings.Builder, digest, second *[64]byte, style VisualStyle, barW, boundingH, cellTextPx float64) {
	barLeft := 1.0
	barTop := 1.0
	barHeight := boundingH - 2.0
	counts := twoBitCounts(*digest)
	edge := style.EdgeColors
	order := firstAppearance(digest)
	orderPos := map[string]int{}
	for i, p := range order {
		orderPos[edge[p]] = i
	}
	colorOrder := map[string]int{}
	for i, c := range edge {
		colorOrder[c] = i
	}

	type band struct {
		color string
		count int
	}
	var used []band
	for i := 0; i < 4; i++ {
		if counts[i] > 0 {
			used = append(used, band{edge[i], counts[i]})
		}
	}
	if len(used) == 0 {
		return
	}
	sort.SliceStable(used, func(a, b int) bool {
		opA, okA := orderPos[used[a].color]
		if !okA {
			opA = 4
		}
		opB, okB := orderPos[used[b].color]
		if !okB {
			opB = 4
		}
		if opA != opB {
			return opA < opB
		}
		coA, ok := colorOrder[used[a].color]
		if !ok {
			coA = 4
		}
		coB, ok := colorOrder[used[b].color]
		if !ok {
			coB = 4
		}
		return coA < coB
	})
	total := 0.0
	for _, b := range used {
		total += math.Pow(float64(b.count), 4)
	}

	// Patch attrs computed below; mirror rs by computing marker info first.
	k := int(math.Floor(barHeight / 12.0))
	if k < 4 {
		k = 4
	}
	if k > 16 {
		k = 16
	}
	leftSlot := int(second[12]) % k
	rightSlot := int(second[13]) % k

	s.WriteString(fmt.Sprintf(
		"<g data-channel=\"color-bar\" data-bar-slots=\"%d\" data-bar-marker-left=\"%d\" data-bar-marker-right=\"%d\">",
		k, leftSlot, rightSlot,
	))
	barCx := barLeft + barW/2.0
	y := barTop
	last := len(used) - 1
	for i, b := range used {
		var h float64
		if i == last {
			h = (barTop + barHeight) - y
		} else {
			h = barHeight * math.Pow(float64(b.count), 4) / total
		}
		letter := bandLetter(b.color)
		if letter != "" {
			s.WriteString(fmt.Sprintf("<g data-color-bar-rank=\"%d\" data-color-bar-band=\"%s\">", i, letter))
		} else {
			s.WriteString(fmt.Sprintf("<g data-color-bar-rank=\"%d\">", i))
		}
		s.WriteString(fmt.Sprintf(
			"<rect x=\"%s\" y=\"%s\" width=\"%s\" height=\"%s\" fill=\"%s\"/>",
			n(barLeft), n(y), n(barW), n(h), escAttr(b.color),
		))
		if letter != "" {
			r := uint32(parseHexByte(b.color[1:3]))
			g := uint32(parseHexByte(b.color[3:5]))
			bb := uint32(parseHexByte(b.color[5:7]))
			_, fg := NucleusColors(r | (g << 8) | (bb << 16))
			fontSize := cellTextPx
			baselineY := (y + h) - 0.22*fontSize
			s.WriteString(fmt.Sprintf(
				"<text x=\"%s\" y=\"%s\" fill=\"%s\" font-size=\"%s\" text-anchor=\"middle\" data-color-bar-letter=\"true\">%s</text>",
				n(barCx), n(baselineY), escAttr(fg), n(fontSize), escText(strings.ToLower(letter)),
			))
		}
		s.WriteString("</g>")
		y += h
	}

	// markers
	slotH := barHeight / float64(k)
	radius := barW * 0.17
	inset := barW * 0.06
	for _, side := range []struct {
		name string
		slot int
	}{{"left", leftSlot}, {"right", rightSlot}} {
		cy := barTop + (float64(side.slot)+0.5)*slotH
		var cx float64
		if side.name == "left" {
			cx = barLeft + inset + radius
		} else {
			cx = barLeft + barW - inset - radius
		}
		s.WriteString(fmt.Sprintf(
			"<circle cx=\"%s\" cy=\"%s\" r=\"%s\" fill=\"#ffffff\" stroke=\"#000000\" stroke-width=\"0.75\" data-bar-marker=\"%s\"/>",
			n(cx), n(cy), n(radius), side.name,
		))
	}
	s.WriteString("</g>")
}

func drawLabelStrips(s *strings.Builder, gridLeft, gridRight, gridTop, gridBottom, nucleusH float64,
	typeName string, prefix, suffix *string, textPx float64, truncatedBytes int, note *string) {
	fontSizeAttr := fmt.Sprintf("font-size=\"%s\"", n(textPx))
	var restText string
	if typeName != "" {
		restText = typeName + ":"
		if prefix != nil {
			restText += " " + *prefix + "..."
		}
	} else if prefix != nil {
		restText = *prefix + "..."
	}
	topCy := gridTop - nucleusH/2.0
	s.WriteString("<g data-channel=\"label-top\">")
	if truncatedBytes >= 0 {
		s.WriteString(fmt.Sprintf(
			"<text x=\"%s\" y=\"%s\" fill=\"#666666\" %s dominant-baseline=\"central\"><tspan fill=\"#a00000\" font-weight=\"bold\">fingerprint of </tspan>%s</text>",
			n(gridLeft), n(topCy), fontSizeAttr, escText(restText),
		))
	} else {
		s.WriteString(fmt.Sprintf(
			"<text x=\"%s\" y=\"%s\" fill=\"#666666\" %s dominant-baseline=\"central\">%s</text>",
			n(gridLeft), n(topCy), fontSizeAttr, escText(restText),
		))
	}
	s.WriteString("</g>")

	if suffix != nil || note != nil {
		bottomCy := gridBottom + nucleusH/2.0
		s.WriteString("<g data-channel=\"label-bottom\">")
		s.WriteString(fmt.Sprintf(
			"<text x=\"%s\" y=\"%s\" fill=\"#666666\" %s text-anchor=\"end\" dominant-baseline=\"central\">",
			n(gridRight), n(bottomCy), fontSizeAttr,
		))
		switch {
		case suffix != nil && note != nil:
			s.WriteString(fmt.Sprintf("<tspan>...%s </tspan>", escText(*suffix)))
			s.WriteString(fmt.Sprintf(
				"<tspan fill=\"#808080\" data-user-note=\"%s\">(%s)</tspan>",
				escAttr(*note), escText(*note),
			))
		case suffix != nil:
			s.WriteString(fmt.Sprintf("...%s", escText(*suffix)))
		case note != nil:
			s.WriteString(fmt.Sprintf(
				"<tspan fill=\"#808080\" data-user-note=\"%s\">(%s)</tspan>",
				escAttr(*note), escText(*note),
			))
		}
		s.WriteString("</text></g>")
	}
}

func b64urlEncode(data []byte) string {
	return b64urlNoPad.EncodeToString(data)
}
