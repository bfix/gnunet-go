package service

import (
	"gnunet/message"
	"gnunet/transport"
)

// Client
type Client struct {
	ch *transport.MsgChannel
}

// NewClient
func NewClient(endp string) (*Client, error) {
	//
	ch, err := transport.NewChannel(endp)
	if err != nil {
		return nil, err
	}
	return &Client{
		ch: transport.NewMsgChannel(ch),
	}, nil
}

func (c *Client) SendRequest(req message.Message) error {
	return c.ch.Send(req)
}

func (c *Client) ReceiveResponse() (message.Message, error) {
	return c.ch.Receive()
}

func (c *Client) Close() error {
	return c.ch.Close()
}
