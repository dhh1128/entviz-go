package entviz

import "testing"

func TestKeccak256KnownAnswers(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{"empty", []byte(""), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"},
		{"abc", []byte("abc"), "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"},
		{"eip55-body", []byte("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"),
			"d385650ce8fdc6db7ee3a091d34814dbc4ce18219ffae52182efff4034d707e5"},
		{"multiblock-200a", bytesRepeat('a', 200),
			"96ea54061def936c4be90b518992fdc6f12f535068a256229aca54267b4d084d"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := keccak256Hex(tt.in)
			if got != tt.want {
				t.Errorf("keccak256Hex(%q) = %s, want %s", tt.name, got, tt.want)
			}
		})
	}
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
