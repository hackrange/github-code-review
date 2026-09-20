/* The Language Server Protocol, on a pipe.
 *
 * LSP is JSON-RPC with a Content-Length header in front of each message.  That
 * is the whole of the transport, and it is ninety lines, so this implements it
 * rather than depending on a package for it.  A security product whose editor
 * plugin pulls a tree of dependencies to frame a JSON message is a security
 * product arguing against itself, and this way the thing we ship to customers
 * is a handful of files anybody can read in an afternoon.
 */
"use strict";

const HEADER_END = "\r\n\r\n";

class Connection {
  constructor(input, output) {
    this.input = input;
    this.output = output;
    this.handlers = new Map();
    this.buffer = Buffer.alloc(0);
    this.nextId = 1;
    this.pending = new Map();
    this.closed = false;
  }

  on(method, handler) { this.handlers.set(method, handler); return this; }

  listen() {
    this.input.on("data", (chunk) => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
      this.drain();
    });
    this.input.on("close", () => { this.closed = true; });
    return this;
  }

  drain() {
    for (;;) {
      const headerEnd = this.buffer.indexOf(HEADER_END);
      if (headerEnd === -1) { return; }
      const header = this.buffer.slice(0, headerEnd).toString("ascii");
      const match = header.match(/content-length:\s*(\d+)/i);
      if (!match) {
        /* A message with no length is one we cannot find the end of, so the
         * only safe thing is to drop what is buffered and wait for the next
         * header rather than guess at a boundary. */
        this.buffer = this.buffer.slice(headerEnd + HEADER_END.length);
        continue;
      }
      const length = parseInt(match[1], 10);
      const start = headerEnd + HEADER_END.length;
      if (this.buffer.length < start + length) { return; }
      const body = this.buffer.slice(start, start + length).toString("utf8");
      this.buffer = this.buffer.slice(start + length);
      let message = null;
      try {
        message = JSON.parse(body);
      } catch (err) {
        continue;
      }
      this.dispatch(message);
    }
  }

  dispatch(message) {
    if (message.id !== undefined && message.method === undefined) {
      const waiting = this.pending.get(message.id);
      if (waiting) {
        this.pending.delete(message.id);
        if (message.error) { waiting.reject(message.error); }
        else { waiting.resolve(message.result); }
      }
      return;
    }

    const handler = this.handlers.get(message.method);
    if (!handler) {
      if (message.id !== undefined) {
        /* A request we do not answer is an error the client can act on; a
         * notification we do not know about is not. */
        this.send({ jsonrpc: "2.0", id: message.id,
                    error: { code: -32601, message: "no such method: " + message.method } });
      }
      return;
    }

    let result;
    try {
      result = handler(message.params || {}, message);
    } catch (err) {
      if (message.id !== undefined) {
        this.send({ jsonrpc: "2.0", id: message.id,
                    error: { code: -32603, message: String(err && err.message || err) } });
      }
      return;
    }

    if (message.id === undefined) { return; }
    Promise.resolve(result).then(
      (value) => this.send({ jsonrpc: "2.0", id: message.id,
                             result: value === undefined ? null : value }),
      (err) => this.send({ jsonrpc: "2.0", id: message.id,
                           error: { code: -32603,
                                    message: String(err && err.message || err) } }));
  }

  send(message) {
    if (this.closed) { return; }
    const body = Buffer.from(JSON.stringify(message), "utf8");
    this.output.write("Content-Length: " + body.length + HEADER_END);
    this.output.write(body);
  }

  notify(method, params) {
    this.send({ jsonrpc: "2.0", method: method, params: params });
  }

  request(method, params) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.send({ jsonrpc: "2.0", id: id, method: method, params: params });
    });
  }
}

module.exports = { Connection };
