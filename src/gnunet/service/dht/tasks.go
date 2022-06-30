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

package dht

import (
	"context"
	"encoding/hex"
	"fmt"
	"gnunet/crypto"
	"gnunet/message"
	"gnunet/transport"
	"gnunet/util"
	"time"

	"github.com/bfix/gospel/logger"
)

// Task interface
type Task interface {
	ID() int                                 // ID of task
	Handle(context.Context, message.Message) // Handle task-related message
	Key() string                             // get the map key for task instance
	Done() bool                              // Expired returns true if the task can be removed
}

//----------------------------------------------------------------------
// Task list for book-keeping
//----------------------------------------------------------------------

// TaskList holds the currently active tasks
type TaskList struct {
	list *util.Map[string, Task] // map of tasks
}

// NewTaskList creates a new task list
func NewTaskList() *TaskList {
	return &TaskList{
		list: util.NewMap[string, Task](),
	}
}

// Add task to list
func (t *TaskList) Add(task Task) bool {
	key := task.Key()
	// if session exists, don't add again
	if _, ok := t.list.Get(key); ok {
		return false
	}
	t.list.Put(key, task)
	return true
}

// Get task from list
func (t *TaskList) Get(key string) (Task, bool) {
	return t.list.Get(key)
}

// Remove task from list
func (t *TaskList) Remove(key string) {
	t.list.Delete(key)
}

// Cleanup removes expired tasks from list
func (t *TaskList) Cleanup() {
	t.list.ProcessRange(func(key string, sess Task) error {
		if sess.Done() {
			t.list.Delete(key)
		}
		return nil
	}, false)
}

//======================================================================
// DHT-P2P-GET tasks:
//
// (1) GetForwardTask:
//     If a DHT-P2P-GET request is forwarded to neighbours, a task
//     links incoming DHT-P2P-RESULTs to the originator of the request.
//     The key used for the task list is "getf:<query>:<forward peer>"
//
// (2) GetTask:
//     If the local peer sends its own DHT-P2P-GET request, incoming
//     DHT-P2P-RESULT(s) are handled in a custom handler  function.
//======================================================================

//----------------------------------------------------------------------
// Task for forwarded GET requests
//----------------------------------------------------------------------

// GetForwardTask
type GetForwardTask struct {
	id         int                 // task identifier
	key        *crypto.HashCode    // GET query key
	forward    *util.PeerID        // peer id (forward peer)
	originator *util.PeerID        // peer id (originator)
	resp       transport.Responder // responder for communicating back to originator
	started    util.AbsoluteTime   // Timestamp of session start
	active     bool                // is the task active?
}

// NewGetForwardTask creates a new task for forwarded GET messages.
func NewGetForwardTask(key *crypto.HashCode, pred, succ *util.PeerID, hdlr transport.Responder) *GetForwardTask {
	return &GetForwardTask{
		id:         util.NextID(),
		key:        key,
		forward:    succ,
		originator: pred,
		resp:       hdlr,
		started:    util.AbsoluteTimeNow(),
		active:     true,
	}
}

// Handle incoming DHT-P2P-RESULT message
func (t *GetForwardTask) Handle(ctx context.Context, msgIn message.Message) {
	// check for correct message type and handler function
	msg, ok := msgIn.(*message.DHTP2PResultMsg)
	if ok {
		// send result message back to originator (result forwarding).
		logger.Printf(logger.INFO, "[dht-task-%d] sending result back to originator", t.ID())
		if err := t.resp.Send(ctx, msg); err != nil {
			logger.Printf(logger.ERROR, "[dht-task-%d] sending result back to originator failed: %s", t.ID(), err.Error())
		}
	}
}

// GetForwardTaskKey returns the key string for a given query/peer combination
func GetForwardTaskKey(query *crypto.HashCode, peer *util.PeerID) string {
	return fmt.Sprintf("getf:%s:%s", hex.EncodeToString(query.Bits), peer.String())
}

// Key returns the task list key for instance
func (t *GetForwardTask) Key() string {
	return GetForwardTaskKey(t.key, t.forward)
}

// Done returns true if the task is expired or closed
func (t *GetForwardTask) Done() bool {
	return !t.active || t.started.Add(time.Hour).Expired()
}

// ID returns the task identifier
func (t *GetForwardTask) ID() int {
	return t.id
}

//----------------------------------------------------------------------
// Task for locally-initiated GET requests:
//
// Before sending the GET request a task is added for the request:
//
//    rc := make(chan any)
//    myTask := NewGetTask(query.Key(), peer, MyCustomHandler, rc)
//    m.tasks.Add(myTask)
//
// If a matching response is received, the custom handler is executed
// in a separate go-routine. A custom handler returns a result (or error) on
// a back channel and should be context-sensitive (termination).
//
// If an asynchronous behaviour is required, use 'ret := <-rc' to wait for
// completion; synchronous execution does not require 'rc' (which can be set
// to nil).
//----------------------------------------------------------------------

// GetTaskHandler is the function prototype for custom handlers:
type GetTaskHandler func(context.Context, *message.DHTP2PResultMsg, chan<- any)

// GetTask for local DHT-P2P-GET requests
type GetTask struct {
	id      int               // task identifier
	query   *crypto.HashCode  // Query from GET
	peer    *util.PeerID      // Peer id the message was send to
	started util.AbsoluteTime // Started timestamp
	hdlr    GetTaskHandler    // Hdlr is a custom message handler
	rc      chan any          // handler result channel
	active  bool              // is task active?
}

// NewGetTask create a new GET task instance
func NewGetTask(key *crypto.HashCode, peer *util.PeerID, hdlr GetTaskHandler, rc chan any) *GetTask {
	return &GetTask{
		id:      util.NextID(),
		query:   key,
		peer:    peer,
		started: util.AbsoluteTimeNow(),
		hdlr:    hdlr,
		rc:      rc,
		active:  true,
	}
}

// Handle incoming DHT-P2P-RESULT message
func (t *GetTask) Handle(ctx context.Context, msgIn message.Message) {
	// check for correct message type and handler function
	msg, ok := msgIn.(*message.DHTP2PResultMsg)
	if ok && t.hdlr != nil {
		logger.Printf(logger.INFO, "[dht-task-%d] handling result message", t.id)
		t.hdlr(ctx, msg, t.rc)
	}
}

// GetForwardTaskKey returns the key string for a given query/peer combination
func GetTaskKey(query *crypto.HashCode, peer *util.PeerID) string {
	return fmt.Sprintf("get:%s:%s", hex.EncodeToString(query.Bits), peer.String())
}

// Key returns the task list key for instance
func (t *GetTask) Key() string {
	return GetTaskKey(t.query, t.peer)
}

// Expired returns true if the task is expired.
func (t *GetTask) Expired(ttl time.Duration) bool {
	return t.started.Add(ttl).Expired()
}

// ID returns the task identifier
func (t *GetTask) ID() int {
	return t.id
}
