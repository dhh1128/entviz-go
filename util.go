package entviz

import "sort"

// assignCellIndices maps each token's index to a cell index on the grid,
// inserting up to three fingerprint-driven blanks (median cell, then the
// ASCII-sort last and first cells) when the grid has spare cells.
func assignCellIndices(tokens []Token, grid Grid, median *Token, sortKeys []Token) []int {
	tokenCount := len(tokens)
	cellCount := grid.Cols * grid.Rows
	ci := make([]int, tokenCount)
	for i := range ci {
		ci[i] = i
	}
	if tokenCount >= cellCount || tokenCount == 0 {
		return ci
	}

	shift := func(start int) {
		for t := range ci {
			if t >= start {
				ci[t]++
			}
		}
	}

	if median != nil {
		shift(median.Index)
	}

	sorted := make([]Token, len(sortKeys))
	copy(sorted, sortKeys)
	sort.SliceStable(sorted, func(a, b int) bool {
		if sorted[a].Text != sorted[b].Text {
			return sorted[a].Text < sorted[b].Text
		}
		return sorted[a].Index < sorted[b].Index
	})

	if tokenCount+1 < cellCount {
		shift(sorted[len(sorted)-1].Index)
	}
	if tokenCount+2 < cellCount {
		shift(sorted[0].Index)
	}
	return ci
}

// twoBitCounts counts each of the four 2-bit patterns across the 256 disjoint
// 2-bit slices of the 64-byte digest.
func twoBitCounts(digest [64]byte) [4]int {
	var counts [4]int
	for _, b := range digest {
		for _, shift := range [4]uint{0, 2, 4, 6} {
			counts[(b>>shift)&0x03]++
		}
	}
	return counts
}

// bandLetter returns the single-letter mnemonic for a palette color, or "" if
// the color is not one of the five palette colors.
func bandLetter(color string) string {
	switch color {
	case "#ffffff":
		return "W"
	case "#e7be00":
		return "G"
	case "#ff3f2f":
		return "R"
	case "#2f3fbf":
		return "B"
	case "#000000":
		return "K"
	}
	return ""
}
