package gostribog

import (
	"hash"
)

type digest struct {
	size  int
	h     [BlockSize]byte
	n     [BlockSize]byte
	sigma [BlockSize]byte
	x     [BlockSize]byte
	nx    int
}

func New512() hash.Hash {
	d := new(digest)
	d.size = 64
	d.Reset()
	return d
}

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

func (d0 *digest) Sum(in []byte) []byte {
	d := *d0
	hash := d.checkSum()
	return append(in, hash...)
}
