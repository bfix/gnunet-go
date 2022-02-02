// This file is part of gnunet-go, a GNUnet-implementation in Golang.
// Copyright (C) 2019, 2020 Bernd Fix  >Y<
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
	"fmt"
	"testing"
	"time"

	"github.com/bfix/gospel/concurrent"
)

// TODO: These test cases fail from time to time for no obvious reason.
// This needs to be investigated.

const (
	SockAddr      = "/tmp/gnunet-go-test.sock"
	TCPAddrClient = "gnunet.org:80"
	TCPAddrServer = "127.0.0.1:9876"
)

type TestChannelServer struct {
	hdlr    chan Channel
	srvc    ChannelServer
	running bool
}

func NewTestChannelServer() *TestChannelServer {
	return &TestChannelServer{
		hdlr:    make(chan Channel),
		srvc:    nil,
		running: false,
	}
}

func (s *TestChannelServer) handle(ch Channel, sig *concurrent.Signaller) {
	buf := make([]byte, 4096)
	for {
		n, err := ch.Read(buf, sig)
		if err != nil {
			break
		}
		_, err = ch.Write(buf[:n], sig)
		if err != nil {
			break
		}
	}
	ch.Close()
}

func (s *TestChannelServer) Start(spec string) (err error) {
	// check if we are already running
	if s.running {
		return fmt.Errorf("Server already running")
	}

	// start channel server
	if s.srvc, err = NewChannelServer(spec, s.hdlr); err != nil {
		return
	}
	s.running = true

	// handle clients
	sig := concurrent.NewSignaller()
	go func() {
		for s.running {
			in := <-s.hdlr
			if in == nil {
				break
			}
			switch x := in.(type) {
			case Channel:
				go s.handle(x, sig)
			}
		}
		s.srvc.Close()
		s.running = false
	}()
	return nil
}

func (s *TestChannelServer) Stop() {
	s.running = false
}

func TestChannelServerTCPSingle(t *testing.T) {
	time.Sleep(time.Second)
	s := NewTestChannelServer()
	err := s.Start("tcp+" + TCPAddrServer)
	defer s.Stop()
	if err != nil {
		t.Fatal(err)
	}
}

func TestChannelServerTCPTwice(t *testing.T) {
	time.Sleep(time.Second)
	s1 := NewTestChannelServer()
	err := s1.Start("tcp+" + TCPAddrServer)
	defer s1.Stop()
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	s2 := NewTestChannelServer()
	err = s2.Start("tcp+" + TCPAddrServer)
	defer s2.Stop()
	if err == nil {
		t.Fatal("SocketServer started twice!!")
	}
}

func TestChannelClientTCP(t *testing.T) {
	time.Sleep(time.Second)
	ch, err := NewChannel("tcp+" + TCPAddrClient)
	if err != nil {
		t.Fatal(err)
	}
	defer ch.Close()

	sig := concurrent.NewSignaller()
	msg := []byte("GET /\n\n")
	n, err := ch.Write(msg, sig)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(msg) {
		t.Fatal("Send size mismatch")
	}
	buf := make([]byte, 4096)
	n = 0
	start := time.Now().Unix()
	for n == 0 && (time.Now().Unix()-start) < 3 {
		if n, err = ch.Read(buf, sig); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("'%s' [%d]\n", string(buf[:n]), n)
}

func TestChannelClientServerTCP(t *testing.T) {
	time.Sleep(time.Second)
	s := NewTestChannelServer()
	err := s.Start("tcp+" + TCPAddrServer)
	defer s.Stop()
	if err != nil {
		t.Fatal(err)
	}

	ch, err := NewChannel("tcp+" + TCPAddrServer)
	if err != nil {
		t.Fatal(err)
	}
	sig := concurrent.NewSignaller()
	msg := []byte("GET /\n\n")
	n, err := ch.Write(msg, sig)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(msg) {
		t.Fatal("Send size mismatch")
	}
	buf := make([]byte, 4096)
	n = 0
	start := time.Now().Unix()
	for n == 0 && (time.Now().Unix()-start) < 3 {
		if n, err = ch.Read(buf, sig); err != nil {
			t.Fatal(err)
		}
	}
	if err = ch.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], msg) {
		t.Fatal("message send/receive mismatch")
	}
}

func TestChannelClientServerSock(t *testing.T) {
	time.Sleep(time.Second)
	s := NewTestChannelServer()
	if err := s.Start("unix+" + SockAddr); err != nil {
		t.Fatal(err)
	}

	ch, err := NewChannel("unix+" + SockAddr)
	if err != nil {
		t.Fatal(err)
	}
	sig := concurrent.NewSignaller()
	msg := []byte("This is just a test -- please ignore...")
	n, err := ch.Write(msg, sig)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(msg) {
		t.Fatal("Send size mismatch")
	}
	buf := make([]byte, 4096)
	n = 0
	start := time.Now().Unix()
	for n == 0 && (time.Now().Unix()-start) < 3 {
		if n, err = ch.Read(buf, sig); err != nil {
			t.Fatal(err)
		}
	}
	if err = ch.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], msg) {
		t.Fatal("message send/receive mismatch")
	}

	s.Stop()
}
