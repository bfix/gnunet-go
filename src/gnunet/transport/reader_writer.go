// This file is part of gnunet-go, a GNUnet-implementation in Golang.
// Copyright (C) 2019-2022 Bernd Fix  >Y<
//
// gnunet-go is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License,
// or (at your option) any later version.
//
// gnunet-go is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL3.0-or-later

package transport

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"gnunet/message"
	"io"

	"github.com/bfix/gospel/data"
)

// WriteMessageDirect writes directly to io.Writer
func WriteMessageDirect(wrt io.Writer, msg message.Message) error {
	dwc := &directWriteCloser{wrt}
	return WriteMessage(context.Background(), dwc, msg)
}

// WriteMessage to io.WriteCloser
func WriteMessage(ctx context.Context, wrt io.WriteCloser, msg message.Message) (err error) {
	// convert message to binary data
	var buf []byte
	if buf, err = data.Marshal(msg); err != nil {
		return err
	}
	// check message header size and packet size
	mh, err := message.GetMsgHeader(buf)
	if err != nil {
		return err
	}
	if len(buf) != int(mh.MsgSize) {
		return errors.New("WriteMessage: message size mismatch")
	}
	// watch dog for write operation
	go func() {
		<-ctx.Done()
		wrt.Close()
	}()
	// perform write operation
	var n int
	if n, err = wrt.Write(buf); err != nil {
		return
	}
	if n != len(buf) {
		err = fmt.Errorf("WriteMessage incomplete (%d of %d)", n, len(buf))
	}
	return
}

//----------------------------------------------------------------------

// ReadMessageDirect reads directly from io.Reader
func ReadMessageDirect(rdr io.Reader, buf []byte) (msg message.Message, err error) {
	drc := &directReadCloser{
		rdr: rdr,
	}
	return ReadMessage(context.Background(), drc, buf)
}

// ReadMessage from io.ReadCloser
func ReadMessage(ctx context.Context, rdr io.ReadCloser, buf []byte) (msg message.Message, err error) {
	// watch dog for write operation
	go func() {
		<-ctx.Done()
		rdr.Close()
	}()
	// get bytes from reader
	if buf == nil {
		buf = make([]byte, 65536)
	}
	get := func(pos, count int) error {
		n, err := rdr.Read(buf[pos : pos+count])
		if err == nil && n != count {
			err = fmt.Errorf("not enough bytes on reader (%d of %d)", n, count)
		}
		return err
	}
	// read header first
	if err := get(0, 4); err != nil {
		return nil, err
	}
	var mh *message.Header
	if mh, err = message.GetMsgHeader(buf[:4]); err != nil {
		return nil, err
	}
	// get rest of message
	if err = get(4, int(mh.MsgSize)-4); err != nil {
		return nil, err
	}
	if msg, err = message.NewEmptyMessage(mh.MsgType); err != nil {
		return nil, err
	}
	if msg == nil {
		return nil, fmt.Errorf("message{%d} is nil", mh.MsgType)
	}
	if err = data.Unmarshal(msg, buf[:mh.MsgSize]); err != nil {
		return nil, err
	}
	return msg, nil
}

//----------------------------------------------------------------------
// Dump message
func Dump(msg message.Message, format string) string {
	switch format {
	case "json":
		buf, err := json.Marshal(msg)
		if err != nil {
			return err.Error()
		}
		return string(buf)
	case "hex":
		buf := new(bytes.Buffer)
		if err := WriteMessageDirect(buf, msg); err != nil {
			return err.Error()
		}
		return hex.EncodeToString(buf.Bytes())
	}
	return "unknown message dump format"
}

//----------------------------------------------------------------------
// helper for wrapped ReadCloser/WriteCloser (close is nop)
//----------------------------------------------------------------------

type directReadCloser struct {
	rdr io.Reader
}

func (drc *directReadCloser) Read(buf []byte) (int, error) {
	return drc.rdr.Read(buf)
}

func (drc *directReadCloser) Close() error {
	return nil
}

type directWriteCloser struct {
	wrt io.Writer
}

func (dwc *directWriteCloser) Write(buf []byte) (int, error) {
	return dwc.wrt.Write(buf)
}

func (dwc *directWriteCloser) Close() error {
	return nil
}
