import contextlib
import socket

from ulrmm.golden import r3


class TestGoldenR3Core(r3.R3Case):
    area = "r3-core"
    servers = True
    hosts = dict(r3.R3Case.hosts, **{"bench-loop.test": "127.0.0.1"})

    def test_nats_ports_shut_with_a_listener(self):
        from ulrmm.helpers import get_nats_ports
        from ulrmm.utils import localhost_port_is_open

        for port in get_nats_ports():
            with socket.socket() as srv:
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # taken already: then the other NATS is the listener
                with contextlib.suppress(OSError):
                    srv.bind(("127.0.0.1", port))
                    srv.listen()
                self.assertFalse(localhost_port_is_open(port))


r3.add_items(TestGoldenR3Core)
