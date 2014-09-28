// Copyright (c) 2014 Dmitry Mikhirev
// This code is licensed under a BSD-style license.
// See the LICENSE file for details.

// Package gostribog implements the GOST R 34.11-2012 hash algorithm
// (stribog) described in RFC6986.
package gostribog

import (
	"hash"
)

// digest represents the partial evaluation of a checksum.
type digest struct {
	size  int
	h     [BlockSize]byte
	n     [BlockSize]byte
	sigma [BlockSize]byte
	x     [BlockSize]byte
	nx    int
}

// New512 returns a new hash.Hash computing the 512-bit stribog checksum.
func New512() hash.Hash {
	d := new(digest)
	d.size = 64
	d.Reset()
	return d
}

// New256 returns a new hash.Hash computing the 256-bit stribog checksum.
func New256() hash.Hash {
	d := new(digest)
	d.size = 32
	d.Reset()
	return d
}

func (d *digest) Reset() {
	var initVal byte
	switch d.size {
	case 32:
		initVal = init256
	case 64:
		initVal = init512
	default:
		panic("wrong digest size")
	}
	for i := range d.n {
		d.n[i] = 0x00
		d.sigma[i] = 0x00
		d.h[i] = initVal
	}
}

func (d *digest) BlockSize() int {
	return BlockSize
}

func (d *digest) Size() int {
	return d.size
}

func (d *digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == BlockSize {
			block(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= BlockSize {
		n := len(p) &^ (BlockSize - 1)
		block(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d *digest) checkSum() []byte {
	if d.nx > 0 {
		block(d, d.x[:d.nx])
	}
	finalize(d)
	return d.h[:d.size]
}

// Sum returns the stribog checksum of the data.
func (d0 *digest) Sum(in []byte) []byte {
	d := *d0
	hash := d.checkSum()
	return append(in, hash...)
}
