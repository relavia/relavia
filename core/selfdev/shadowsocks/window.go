package shadowsocks

// Sliding-window replay filter for SIP022 UDP sessions
// (3.2.4), modelled on the WireGuard construction the SIP
// points at: a packet ID is acceptable if it is newer than the
// highest seen ID, or within the window behind it and not yet
// seen. Check never mutates - per the SIP, window state updates
// only after the packet's header has been fully validated;
// callers Check, validate, then Add.

const windowSize = 2048

type slidingWindow struct {
	max  uint64
	bits [windowSize / 64]uint64
	seen bool
}

// check reports whether id is acceptable (not a duplicate, not
// older than the window). It does not record id.
func (w *slidingWindow) check(id uint64) bool {
	if !w.seen {
		return true
	}
	if id > w.max {
		return true
	}
	diff := w.max - id
	if diff >= windowSize {
		return false
	}
	return w.bits[diff/64]&(1<<(diff%64)) == 0
}

// add records id as seen, sliding the window if id advances it.
func (w *slidingWindow) add(id uint64) {
	if !w.seen {
		w.seen = true
		w.max = id
		w.bits[0] |= 1
		return
	}
	if id > w.max {
		shift := id - w.max
		if shift >= windowSize {
			for i := range w.bits {
				w.bits[i] = 0
			}
		} else {
			// Move bit i (distance d from old max) to distance
			// d+shift from the new max.
			nb := [windowSize / 64]uint64{}
			for d := uint64(0); d+shift < windowSize; d++ {
				if w.bits[d/64]&(1<<(d%64)) != 0 {
					nb[(d+shift)/64] |= 1 << ((d + shift) % 64)
				}
			}
			w.bits = nb
		}
		w.max = id
		w.bits[0] |= 1
		return
	}
	diff := w.max - id
	if diff < windowSize {
		w.bits[diff/64] |= 1 << (diff % 64)
	}
}
