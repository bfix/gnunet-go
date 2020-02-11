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
)

const (
	SOCK_ADDR       = "/tmp/gnunet-go-test.sock"
	TCP_ADDR_CLIENT = "gnunet.org:80"
	TCP_ADDR_SERVER = "127.0.0.1:12086"
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

func (s *TestChannelServer) handle(ch Channel) {
	buf := make([]byte, 4096)
	for {
		n, err := ch.Read(buf)
		if err != nil {
			break
		}
		_, err = ch.Write(buf[:n])
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
	go func() {
		for s.running {
			select {
			case in := <-s.hdlr:
				if in == nil {
					break
				}
				switch x := in.(type) {
				case Channel:
					go s.handle(x)
				}
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
	if err := s.Start("tcp+" + TCP_ADDR_SERVER); err != nil {
		t.Fatal(err)
	}
	s.Stop()
}

func TestChannelServerTCPTwice(t *testing.T) {
	time.Sleep(time.Second)
	s1 := NewTestChannelServer()
	if err := s1.Start("tcp+" + TCP_ADDR_SERVER); err != nil {
		t.Fatal(err)
	}
	s2 := NewTestChannelServer()
	if err := s2.Start("tcp+" + TCP_ADDR_SERVER); err == nil {
		t.Fatal("SocketServer started twice!!")
	}
	s1.Stop()
}

func TestChannelClientTCP(t *testing.T) {
	time.Sleep(time.Second)
	ch, err := NewChannel("tcp+" + TCP_ADDR_CLIENT)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("GET /\n\n")
	n, err := ch.Write(msg)
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
		if n, err = ch.Read(buf); err != nil {
			t.Fatal(err)
		}
	}
	if err = ch.Close(); err != nil {
		t.Fatal(err)
	}
	t.Logf("'%s' [%d]\n", string(buf[:n]), n)
}

func TestChannelClientServerTCP(t *testing.T) {
	time.Sleep(time.Second)
	s := NewTestChannelServer()
	if err := s.Start("tcp+" + TCP_ADDR_SERVER); err != nil {
		t.Fatal(err)
	}

	ch, err := NewChannel("tcp+" + TCP_ADDR_SERVER)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("GET /\n\n")
	n, err := ch.Write(msg)
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
		if n, err = ch.Read(buf); err != nil {
			t.Fatal(err)
		}
	}
	if err = ch.Close(); err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(buf[:n], msg) != 0 {
		t.Fatal("message send/receive mismatch")
	}

	s.Stop()
}

func TestChannelClientServerSock(t *testing.T) {
	time.Sleep(time.Second)
	s := NewTestChannelServer()
	if err := s.Start("unix+" + SOCK_ADDR); err != nil {
		t.Fatal(err)
	}

	ch, err := NewChannel("unix+" + SOCK_ADDR)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("This is just a test -- please ignore...")
	n, err := ch.Write(msg)
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
		if n, err = ch.Read(buf); err != nil {
			t.Fatal(err)
		}
	}
	if err = ch.Close(); err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(buf[:n], msg) != 0 {
		t.Fatal("message send/receive mismatch")
	}

	s.Stop()
}
