// Copyright 2013 The Gorilla WebSocket Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

// Hub maintains the set of active clients and broadcasts messages to the
// clients.

type SingleChat struct {
	// 目标username
	to string
	// 消息
	message string

	// form username
	from string
}

type Hub struct {
	// Registered clients.
	clients map[string]*Client

	// Inbound messages from the clients.
	broadcast chan []byte

	// Inbound messages from the clients.
	singleChat chan *SingleChat

	// Register requests from the clients.
	register chan *Client

	// Unregister requests from clients.
	unregister chan *Client
}

func newHub() *Hub {
	return &Hub{
		broadcast:  make(chan []byte),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		clients:    make(map[string]*Client),
		singleChat: make(chan *SingleChat),
	}
}

func (h *Hub) run() {
	for {
		select {
		case client := <-h.register:
			h.clients[client.username] = client
		case client := <-h.unregister:
			if _, ok := h.clients[client.username]; ok {
				delete(h.clients, client.username)
				close(client.send)
			}
		case message := <-h.broadcast:
			for _, client := range h.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(h.clients, client.username)
				}
			}
		case target := <-h.singleChat:
			client := h.clients[target.to]
			select {
			case client.send <- []byte(target.message):
			default:
				close(client.send)
				delete(h.clients, client.username)
			}
		}
	}
}
