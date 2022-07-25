//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package v0

import "io"

type PipeWrapper struct {
	r         *io.PipeReader
	w         *io.PipeWriter
	exchanged int // basically we only use this during testing, to track bytes exchanged
}

func (wrapper *PipeWrapper) Write(p []byte) (int, error) {
	n, err := wrapper.w.Write(p)
	wrapper.exchanged += n
	return n, err
}

func (wrapper *PipeWrapper) Read(p []byte) (int, error) {
	n, err := wrapper.r.Read(p)
	wrapper.exchanged += n
	return n, err
}

func NewPipeWrappers() (*PipeWrapper, *PipeWrapper) {
	leftOut, leftIn := io.Pipe()
	rightOut, rightIn := io.Pipe()
	return &PipeWrapper{r: leftOut, w: rightIn}, &PipeWrapper{r: rightOut, w: leftIn}
}
