// Copyright (c) 2014 Dmitry Mikhirev
// This code is licensed under a BSD-style license.
// See the LICENSE file for details.

package gostribog

import (
	"unsafe"
)

var mult [8][256]uint64

func addModulo(a, b *[BlockSize]byte) {
	var t uint
	for i := BlockSize - 1; i >= 0; i-- {
		t = uint(a[i]) + uint(b[i]) + (t >> 8)
		a[i] = byte(t & uint(0xff))
	}
}

func xorChunk(a, b, r *[BlockSize]byte) {
	a64 := (*[BlockSize / 8]uint64)(unsafe.Pointer(a))
	b64 := (*[BlockSize / 8]uint64)(unsafe.Pointer(b))
	r64 := (*[BlockSize / 8]uint64)(unsafe.Pointer(r))
	for i := range *r64 {
		r64[i] = a64[i] ^ b64[i]
	}
}

func spl(state *[BlockSize]byte) {
	// SP
	var t [BlockSize]byte
	for i := 0; i < BlockSize/8; i++ {
		for j := 0; j < 8; j++ {
			t[(i<<3)+j] = sbox[state[i+(j<<3)]]
		}
	}

	//L
	for i := 0; i < BlockSize/8; i++ {
		var v uint64
		for k := 0; k < 8; k++ {
			for j := 0; j < 8; j++ {
				if t[(i<<3)+k]&(byte(1)<<(7-uint(j))) != 0 {
					v ^= a[(k<<3)+j]
				}
			}
		}
		for k := 0; k < 8; k++ {
			state[(i<<3)+k] = byte((v & (uint64(0xFF) << ((7 - uint(k)) << 3))) >> ((7 - uint(k)) << 3))
		}
	}
}

func e(k, m, s *[BlockSize]byte) {
	xorChunk(m, k, s)
	for i := range c {
		spl(s)
		xorChunk(k, &c[i], k)
		spl(k)
		xorChunk(s, k, s)
	}
}

func gN(h, m, n *[BlockSize]byte) {
	var k, s [BlockSize]byte
	xorChunk(h, n, &k)
	spl(&k)
	e(&k, m, &s)
	xorChunk(&s, h, &s)
	xorChunk(&s, m, h)
}

func block(d *digest, p []byte) {
	h := d.h
	n := d.n
	sigma := d.sigma
	for len(p) >= BlockSize {
		var m [BlockSize]byte
		for i, b := range p[:BlockSize] {
			m[i] = b
		}

		gN(&h, &m, &n)

		addModulo(&n, &v512)
		addModulo(&sigma, &m)

		p = p[BlockSize:]
	}
	if len(p) > 0 {
		// the very last piece of data
		lb := len(p) * 8
		l := [BlockSize]byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			byte((lb & 0xff00) >> 8),
			byte(lb & 0xff),
		}
		var m [BlockSize]byte
		m[BlockSize-len(p)-1] = 1
		for i, b := range p {
			m[BlockSize-len(p)+i] = b
		}
		gN(&h, &m, &n)

		addModulo(&n, &l)
		addModulo(&sigma, &m)
	}
	d.h = h
	d.n = n
	d.sigma = sigma
}

func finalize(d *digest) {
	h := d.h
	gN(&h, &d.n, &v0)
	gN(&h, &d.sigma, &v0)
	d.h = h
}
