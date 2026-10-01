package build

// TextSanitizer keeps upstream ANSI/OSC sequences and carriage-return
// animation out of logs and records. State survives tool writes, including
// escape sequences split across chunks. Captured command bytes are
// deliberately not passed through this sanitizer.
type TextSanitizer struct {
	state byte
}

func (s *TextSanitizer) Clean(data []byte) []byte {
	clean := make([]byte, 0, len(data))
	for _, b := range data {
		switch s.state {
		case 1: // ESC sequence, possibly with intermediate bytes.
			switch b {
			case '[':
				s.state = 2
			case ']', 'P', 'X', '^', '_':
				s.state = 3
			default:
				if b < 0x20 || b > 0x2f {
					s.state = 0
				}
			}
		case 2: // CSI ends at its final byte.
			if b >= 0x40 && b <= 0x7e {
				s.state = 0
			}
		case 3: // OSC/control string ends at BEL or ESC-backslash.
			if b == '\a' {
				s.state = 0
			} else if b == 0x1b {
				s.state = 4
			}
		case 4:
			if b == '\\' {
				s.state = 0
			} else if b != 0x1b {
				s.state = 3
			}
		default:
			if b == 0x1b {
				s.state = 1
			} else if b == '\n' || b == '\t' || (b >= 0x20 && b != 0x7f) {
				clean = append(clean, b)
			}
		}
	}
	return clean
}

// PlainText returns text without terminal control sequences.
func PlainText(text string) string {
	var sanitizer TextSanitizer
	return string(sanitizer.Clean([]byte(text)))
}
