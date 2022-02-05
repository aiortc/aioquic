var transport = new WebTransport('https://localhost:4433/wt');
transport.closed.then(console.log, console.error);
await transport.ready;
var { readable, writable } = transport.datagrams;
var number_of_datagrams_received = 0;
readable
  .pipeTo(
    new WritableStream({
      write(datagram) {
        console.log({ number_of_datagrams_received, datagram });
        ++number_of_datagrams_received;
      },
      close() {
        console.log('closed');
      },
    })
  )
  .then(console.log, console.error);
var writer = writable.getWriter();
await writer.write(new Uint8Array([65]));
