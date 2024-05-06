//
// co.go
//
// Copyright (c) 2019-2023 Markku Rossi
//
// All rights reserved.
//
// Chou Orlandi OT - The Simplest Protocol for Oblivious Transfer.
//  - https://eprint.iacr.org/2015/267.pdf

/*

This implementation is derived from the EMP Toolkit's co.h
(https://github.com/emp-toolkit/emp-ot/blob/master/emp-ot/co.h)
with original license as follows:

MIT License

Copyright (c) 2018 Xiao Wang (wangxiao1254@gmail.com)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Enquiries about further applications and development opportunities are welcome.

*/

package ot

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"math/big"
	"time"
)

var (
	bo    = binary.BigEndian
	_  OT = &CO{}
)

// COSender implements CO OT sender.
type COSender struct {
	curve elliptic.Curve
}

// NewCOSender creates a new CO OT sender.
func NewCOSender() *COSender {
	return &COSender{
		curve: elliptic.P256(),
	}
}

// Curve returns sender's elliptic curve.
func (s *COSender) Curve() elliptic.Curve {
	return s.curve
}

// NewTransfer creates a new OT transfer for the values.
func (s *COSender) NewTransfer(m0, m1 []byte) (*COSenderXfer, error) {
	curveParams := s.curve.Params()

	// a <- Zp
	a, err := rand.Int(rand.Reader, curveParams.N)
	if err != nil {
		return nil, err
	}

	// A = G^a
	Ax, Ay := s.curve.ScalarBaseMult(a.Bytes())

	// Aa = A^a
	Aax, Aay := s.curve.ScalarMult(Ax, Ay, a.Bytes())

	// a:    {x,y}
	// a^-1: {x,-y}
	// AaInv = {Aax, -Aay}
	AaInvx := big.NewInt(0).Set(Aax)
	AaInvy := big.NewInt(0).Sub(curveParams.P, Aay)

	return &COSenderXfer{
		curve:  s.curve,
		hash:   sha256.New(),
		m0:     m0,
		m1:     m1,
		a:      a,
		Ax:     Ax,
		Ay:     Ay,
		AaInvx: AaInvx,
		AaInvy: AaInvy,
	}, nil
}

// COSenderXfer implements sender OT transfer.
type COSenderXfer struct {
	curve  elliptic.Curve
	hash   hash.Hash
	m0     []byte
	m1     []byte
	a      *big.Int
	Ax     *big.Int
	Ay     *big.Int
	AaInvx *big.Int
	AaInvy *big.Int
	e0     []byte
	e1     []byte
}

// A returns sender's random value.
func (s *COSenderXfer) A() (x, y []byte) {
	return s.Ax.Bytes(), s.Ay.Bytes()
}

// ReceiveB receives receiver's selection.
func (s *COSenderXfer) ReceiveB(x, y []byte) {
	bx := big.NewInt(0).SetBytes(x)
	by := big.NewInt(0).SetBytes(y)

	bx, by = s.curve.ScalarMult(bx, by, s.a.Bytes())
	bax, bay := s.curve.Add(bx, by, s.AaInvx, s.AaInvy)

	s.e0 = xor(kdf(s.hash, bx, by, 0, nil), s.m0)
	s.e1 = xor(kdf(s.hash, bax, bay, 0, nil), s.m1)
}

// E returns sender's encrypted messages.
func (s *COSenderXfer) E() (e0, e1 []byte) {
	return s.e0, s.e1
}

// COReceiver implements CO OT receiver.
type COReceiver struct {
	curve elliptic.Curve
}

// NewCOReceiver creates a new OT receiver.
func NewCOReceiver(curve elliptic.Curve) *COReceiver {
	return &COReceiver{
		curve: curve,
	}
}

// NewTransfer creates a new OT transfer for the selection bit.
func (r *COReceiver) NewTransfer(bit uint) (*COReceiverXfer, error) {
	curveParams := r.curve.Params()

	// b <= Zp
	b, err := rand.Int(rand.Reader, curveParams.N)
	if err != nil {
		return nil, err
	}

	return &COReceiverXfer{
		curve: r.curve,
		hash:  sha256.New(),
		bit:   bit,
		b:     b,
	}, nil
}

// COReceiverXfer implements receiver OT transfer.
type COReceiverXfer struct {
	curve elliptic.Curve
	hash  hash.Hash
	bit   uint
	b     *big.Int
	Bx    *big.Int
	By    *big.Int
	Asx   *big.Int
	Asy   *big.Int
}

// ReceiveA receives sender's random value.
func (r *COReceiverXfer) ReceiveA(x, y []byte) {
	Ax := big.NewInt(0).SetBytes(x)
	Ay := big.NewInt(0).SetBytes(y)

	Bx, By := r.curve.ScalarBaseMult(r.b.Bytes())
	if r.bit != 0 {
		Bx, By = r.curve.Add(Bx, By, Ax, Ay)
	}
	r.Bx = Bx
	r.By = By

	Asx, Asy := r.curve.ScalarMult(Ax, Ay, r.b.Bytes())
	r.Asx = Asx
	r.Asy = Asy
}

// B returns receiver's selection.
func (r *COReceiverXfer) B() (x, y []byte) {
	return r.Bx.Bytes(), r.By.Bytes()
}

// ReceiveE receives encrypted messages from the sender and returns
// the result value.
func (r *COReceiverXfer) ReceiveE(e0, e1 []byte) []byte {
	var result []byte

	data := kdf(r.hash, r.Asx, r.Asy, 0, nil)

	if r.bit != 0 {
		result = xor(data, e1)
	} else {
		result = xor(data, e0)
	}
	return result
}

func kdf(hash hash.Hash, x, y *big.Int, id uint64, digest []byte) []byte {
	hash.Reset()
	hash.Write(x.Bytes())
	hash.Write(y.Bytes())

	var tmp [8]byte
	bo.PutUint64(tmp[:], id)
	hash.Write(tmp[:])

	return hash.Sum(digest)
}

func xor(a, b []byte) []byte {
	l := len(a)
	if len(b) < l {
		l = len(b)
	}
	for i := 0; i < l; i++ {
		a[i] ^= b[i]
	}
	return a[:l]
}

// CO implements CO OT as the OT interface.
type CO struct {
	curve  elliptic.Curve
	hash   hash.Hash
	digest []byte
	io     IO
}

// NewCO creates a new CO OT implementing the OT interface.
func NewCO() *CO {
	return &CO{
		curve:  elliptic.P256(),
		hash:   sha256.New(),
		digest: make([]byte, sha256.Size),
	}
}

// InitSender initializes the OT sender.
func (co *CO) InitSender(io IO) error {
	co.io = io
	if err := SendString(io, co.curve.Params().Name); err != nil {
		return err
	}
	return io.Flush()
}

// InitReceiver initializes the OT receiver.
func (co *CO) InitReceiver(io IO) error {
	co.io = io

	name, err := ReceiveString(io)
	if err != nil {
		return err
	}
	if name != co.curve.Params().Name {
		return fmt.Errorf("invalid curve %s, expected %s",
			name, co.curve.Params().Name)
	}
	return nil
}

// Send sends the wire labels with OT.
func (co *CO) Send(wires []Wire) error {
	fmt.Println("Normal Send")
	for _, wire := range wires {
		var labelData LabelData
		wire.L0.GetData(&labelData)
		// fmt.Println("Send L0", labelData)
		if err := co.io.SendData(labelData[:]); err != nil {
			return err
		}
		wire.L1.GetData(&labelData)
		// fmt.Println("Send L1", labelData)
		if err := co.io.SendData(labelData[:]); err != nil {
			return err
		}
	}
	return co.io.Flush()
}

// Receive receives the wire labels with OT based on the flag values.
func (co *CO) Receive(flags []bool, result []Label) error {
	fmt.Println("Normal Receive")
	ec_time := time.Now()
	for i := range flags {
		label0, err := co.io.ReceiveData()
		if err != nil {
			return err
		}
		label1, err := co.io.ReceiveData()
		if err != nil {
			return err
		}

		// Select which label to store based on the flag
		if flags[i] {
			result[i].SetBytes(label1)
			// fmt.Println("Receive L1", label1)
		} else {
			result[i].SetBytes(label0)
			// fmt.Println("Receive L0", label0)
		}
	}
	fmt.Println("EC Time", time.Since(ec_time))
	return nil
}
