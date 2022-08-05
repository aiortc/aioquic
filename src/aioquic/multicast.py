import multicast_glue

global _loop, _libhandle
_loop = None
_libhandle = None


def added_sock_cb(loop, handle, fd, do_read):
    global _libhandle
    assert (_libhandle is not None)

    # sock = socket.socket(fileno=fd)
    def read_handler(do_read, handle, fd):
        global _libhandle
        assert (_libhandle is not None)
        return multicast_glue.receive_packets(_libhandle, do_read, handle, fd)

    loop.add_reader(fd, read_handler, do_read, handle, fd)
    return 0


def removed_sock_cb(loop, fd):
    # sock = socket.socket(fileno=fd)
    loop.remove_reader(fd)
    return 0


def got_packet(listener, size, data, port):
    listener.preconnection.got_mc(listener, size, data, port)
    return 0


def do_join(listener):
    global _loop, _libhandle
    if _loop is None:
        if listener.loop is None:
            raise Exception("joining with no asyncio" +
                            " loop attached to connection")
            return False
        _libhandle = multicast_glue.initialize(listener.loop, added_sock_cb,
                                               removed_sock_cb)
        _loop = listener.loop
        assert (_libhandle is not None)

    remote = listener.remote_endpoint.address[0]
    local = listener.local_endpoint.address[0]

    if _loop is not listener.loop:
        # if we hit this, we need to maintain a dict to keep a separate
        # libhandle per loop
        raise Exception("not yet supported: joining with multiple" +
                        " different asyncio loops")
    join_ctx = multicast_glue.join(_libhandle, listener,
                                   remote,
                                   local,
                                   int(listener.local_endpoint.port),
                                   got_packet)
    listener._join_ctx = join_ctx
    return (join_ctx is not None)


def do_leave(listener):
    if not hasattr(listener, '_join_ctx') or listener._join_ctx is None:
        raise Exception('leaving a connection not joined')

    multicast_glue.leave(listener._join_ctx)
    listener._join_ctx = None