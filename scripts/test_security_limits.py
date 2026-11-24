"""Check the local upstream's connection budget with two normal clients."""
import http.client
from contextlib import closing
from pathlib import Path
import sys
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from runtime import LocalUpstreamServer, MockService


class ConnectionLimits(unittest.TestCase):
    def test_absolute_lifetime_with_normal_reads(self):
        class ShortLived(LocalUpstreamServer):
            connection_lifetime = .5

        handler = MockService("DEV", {"reader": "public-test-value"}).handler()
        with ShortLived(("127.0.0.1", 0), handler) as server:
            worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01})
            worker.start()
            try:
                with closing(http.client.HTTPConnection(*server.server_address, timeout=2)) as conn:
                    def read():
                        conn.request("GET", "/service/status", headers={"Authorization":"Bearer public-test-value"})
                        response = conn.getresponse()
                        response.read()
                        return response.status
                    for _ in range(3):
                        self.assertEqual(read(), 200)
                        time.sleep(.05)
                    # A live HTTP/1.1 connection with recent activity still has an absolute end.
                    time.sleep(.5)
                    with self.assertRaises((http.client.RemoteDisconnected, ConnectionResetError, BrokenPipeError)):
                        read()
                    conn.close()
                    self.assertEqual(read(), 200)
            finally:
                server.shutdown()
                worker.join()

    def test_idle_client_releases_worker(self):
        released = threading.Event()

        class OneWorker(LocalUpstreamServer):
            max_connections = 1

            def process_request_thread(self, request, address):
                try:
                    super().process_request_thread(request, address)
                finally:
                    released.set()

        handler = MockService("DEV", {"reader": "fixture-only"}).handler()
        handler.timeout = 0.4
        with OneWorker(("127.0.0.1", 0), handler) as server:
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
            thread.start()
            try:
                def read(conn):
                    conn.request("GET", "/service/status", headers={"Authorization": "Bearer fixture-only"})
                    res = conn.getresponse()
                    res.read()
                    return res.status

                with closing(http.client.HTTPConnection(*server.server_address, timeout=2)) as first:
                    self.assertEqual(read(first), 200)
                    with closing(http.client.HTTPConnection(*server.server_address, timeout=2)) as second:
                        with self.assertRaises((http.client.RemoteDisconnected, ConnectionResetError, BrokenPipeError)):
                            read(second)
                    self.assertTrue(released.wait(2))
                    with closing(http.client.HTTPConnection(*server.server_address, timeout=2)) as later:
                        self.assertEqual(read(later), 200)
            finally:
                server.shutdown()
                thread.join()


if __name__ == "__main__":
    unittest.main()
