import asyncio
import http.client
import os
import unittest
from collections.abc import Awaitable, Callable
from unittest.mock import AsyncMock, Mock, patch

with patch.dict(os.environ, {"REMOTE_PAC_URL": "http://unused.invalid/proxy.pac"}):
    import proxy_server as proxy


class RecordingWriter:
    def __init__(self, retain: bool = True) -> None:
        self.data = bytearray()
        self.count = 0
        self.retain = retain
        self.written = asyncio.Event()

    def write(self, data: bytes) -> None:
        self.count += len(data)
        if self.retain:
            self.data.extend(data)
        self.written.set()

    async def drain(self) -> None:
        pass


class ResponseTests(unittest.IsolatedAsyncioTestCase):
    async def relay(self, data: bytes, method: str = "GET") -> bytes:
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        reader.feed_eof()
        writer = RecordingWriter()
        await proxy._relay_response(
            reader, writer, "example.com", 80, "DIRECT", "DIRECT", method,
        )
        return bytes(writer.data)

    async def test_fixed_response_and_connection_headers(self):
        result = await self.relay(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
            b"Connection: keep-alive, X-Internal\r\nX-Internal: secret\r\n"
            b"Set-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\nhello"
        )
        self.assertTrue(result.endswith(b"\r\n\r\nhello"))
        self.assertIn(b"Connection: close\r\n", result)
        self.assertNotIn(b"X-Internal", result)
        self.assertEqual(result.count(b"Set-Cookie:"), 2)

    async def test_chunked_response_and_trailers(self):
        result = await self.relay(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
            b"Trailer: Digest\r\n\r\n5;ext=yes\r\nhello\r\n"
            b"0\r\nDigest: ignored\r\n\r\n"
        )
        self.assertIn(b"Transfer-Encoding: chunked\r\n", result)
        self.assertNotIn(b"Content-Length", result)
        self.assertNotIn(b"Digest", result)
        self.assertTrue(result.endswith(b"5\r\nhello\r\n0\r\n\r\n"))

    async def test_transfer_encoding_overrides_content_length(self):
        result = await self.relay(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
            b"Content-Length: 1\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
        )
        self.assertNotIn(b"Content-Length", result)
        self.assertTrue(result.endswith(b"5\r\nhello\r\n0\r\n\r\n"))

    async def test_head_and_bodyless_statuses(self):
        for method, status in (("HEAD", 200), ("GET", 204), ("GET", 304)):
            with self.subTest(method=method, status=status):
                result = await self.relay(
                    (
                        f"HTTP/1.1 {status} Test\r\nTransfer-Encoding: chunked\r\n"
                        "\r\n"
                    ).encode(), method,
                )
                self.assertTrue(result.startswith(f"HTTP/1.1 {status}".encode()))
                self.assertTrue(result.endswith(b"\r\n\r\n"))

    async def test_interim_responses(self):
        result = await self.relay(
            b"HTTP/1.1 100 Continue\r\n\r\n"
            b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\n"
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        )
        self.assertIn(b"HTTP/1.1 100 Continue\r\n\r\n", result)
        self.assertIn(b"HTTP/1.1 103 Early Hints\r\n", result)
        self.assertTrue(result.endswith(b"\r\n\r\nok"))

    async def test_chunked_response_streams_before_completion(self):
        reader = asyncio.StreamReader()
        reader.feed_data(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"5\r\nhello\r\n"
        )
        writer = RecordingWriter()
        task = asyncio.create_task(proxy._relay_response(
            reader, writer, "example.com", 80, "DIRECT", "DIRECT", "GET",
        ))
        try:
            async with asyncio.timeout(1):
                while b"hello" not in writer.data:
                    writer.written.clear()
                    await writer.written.wait()
            self.assertFalse(task.done())
            reader.feed_data(b"0\r\n\r\n")
            await task
            self.assertTrue(writer.data.endswith(b"0\r\n\r\n"))
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def test_response_exceeds_old_64_mib_limit(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
        writer = RecordingWriter(retain=False)
        task = asyncio.create_task(proxy._relay_response(
            reader, writer, "example.com", 80, "DIRECT", "DIRECT", "GET",
        ))
        size = 65 * 1024 * 1024
        try:
            reader.feed_data(f"{size:x}\r\n".encode())
            for _ in range(size // 65536):
                reader.feed_data(b"x" * 65536)
                await asyncio.sleep(0)
            reader.feed_data(b"\r\n0\r\n\r\n")
            reader.feed_eof()
            await asyncio.wait_for(task, 10)
            self.assertGreater(writer.count, size)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def test_chunk_reads_use_idle_not_header_timeout(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b"5\r\nhello\r\n")

        async def finish():
            await asyncio.sleep(0.03)
            reader.feed_data(b"0\r\n\r\n")

        task = asyncio.create_task(finish())
        with patch.object(proxy, "HEADER_TIMEOUT", 0.001), patch.object(proxy, "IDLE_TIMEOUT", 1):
            chunks = [chunk async for chunk in proxy._iter_chunked(reader)]
        await task
        self.assertEqual(b"".join(chunks), b"hello")

    async def test_invalid_chunks_do_not_signal_success(self):
        for body in (
            b"5\r\nhello",
            b"5\r\nhelloXX0\r\n\r\n",
            b"5\r\nhello\r\n",
            b"5\r\nhello\r\n0\r\n",
            b"5\r\nhello\r\n0\r\nDigest: value\r\n",
            b"+5\r\nhello\r\n0\r\n\r\n",
        ):
            with self.subTest(body=body):
                with self.assertLogs(proxy.logger, level="WARNING"):
                    result = await self.relay(
                        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + body
                    )
                self.assertNotIn(b"Content-Length:", result)
                self.assertFalse(result.endswith(b"0\r\n\r\n"))

    async def test_chunk_timeout_raises(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b"5\r\nhello")
        with patch.object(proxy, "IDLE_TIMEOUT", 0.01):
            with self.assertRaises(proxy._ChunkedDecodeError):
                async for _ in proxy._iter_chunked(reader):
                    pass

    async def test_bad_response_headers_return_gateway_error(self):
        for response in (
            b"",
            b"not HTTP\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: invalid\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n",
        ):
            with self.subTest(response=response):
                with self.assertLogs(proxy.logger, level="WARNING"):
                    result = await self.relay(response)
                self.assertTrue(result.startswith(b"HTTP/1.1 502"))


class ConnectionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.servers: list[asyncio.Server] = []
        self.writers: list[asyncio.StreamWriter] = []
        self.tasks: set[asyncio.Task] = set()
        self.errors: list[Exception] = []
        self.route_patch = patch.object(proxy, "get_route", AsyncMock(return_value="DIRECT"))
        self.route_patch.start()
        self.addCleanup(self.route_patch.stop)
        self.proxy_port = await self.listen(proxy.handle_connection)

    async def asyncTearDown(self):
        for writer in self.writers:
            writer.close()
        await asyncio.gather(
            *(writer.wait_closed() for writer in self.writers), return_exceptions=True,
        )
        for server in self.servers:
            server.close()
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        await asyncio.gather(*(server.wait_closed() for server in self.servers))
        self.assertEqual(self.errors, [])

    async def listen(
        self,
        handler: Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]],
    ) -> int:
        async def tracked(reader, writer):
            task = asyncio.current_task()
            self.tasks.add(task)
            try:
                await handler(reader, writer)
            except Exception as e:
                self.errors.append(e)
            finally:
                writer.close()

        server = await asyncio.start_server(tracked, "127.0.0.1", 0)
        self.servers.append(server)
        return server.sockets[0].getsockname()[1]

    async def connect(self, port=None):
        reader, writer = await asyncio.open_connection("127.0.0.1", port or self.proxy_port)
        self.writers.append(writer)
        return reader, writer

    async def request(self, request: bytes) -> bytes:
        reader, writer = await self.connect()
        writer.write(request)
        await writer.drain()
        return await asyncio.wait_for(reader.read(), 2)

    async def test_upload_and_continue(self):
        received = []

        async def origin(reader, writer):
            head = await reader.readuntil(b"\r\n\r\n")
            received.append(head)
            received.append(await reader.readexactly(5))
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            await writer.drain()

        port = await self.listen(origin)
        for chunked in (False, True):
            reader, writer = await self.connect()
            framing = "Transfer-Encoding: chunked" if chunked else "Content-Length: 5"
            writer.write(
                f"POST http://127.0.0.1:{port}/upload?q=1 HTTP/1.1\r\n"
                f"Host: ignored\r\nExpect: 100-continue\r\n{framing}\r\n"
                "Connection: X-Remove\r\nX-Remove: secret\r\n\r\n".encode()
            )
            await writer.drain()
            self.assertEqual(
                await reader.readuntil(b"\r\n\r\n"), b"HTTP/1.1 100 Continue\r\n\r\n",
            )
            writer.write(b"5\r\nhello\r\n0\r\nDigest: ignored\r\n\r\n" if chunked else b"hello")
            await writer.drain()
            response = await asyncio.wait_for(reader.read(), 2)
            self.assertTrue(response.endswith(b"\r\n\r\nok"))
            self.assertIn(b"Content-Length: 2\r\n", response)
            self.assertEqual(received[-1], b"hello")
            self.assertIn(b"POST /upload?q=1 HTTP/1.1", received[-2])
            self.assertIn(b"content-length: 5\r\n", received[-2])
            self.assertNotIn(b"expect:", received[-2])
            self.assertNotIn(b"x-remove:", received[-2])

    async def test_invalid_requests(self):
        for target, headers in (
            ("http://example.com:invalid/", ""),
            ("http://example.com:65536/", ""),
            ("http://example.com:0/", ""),
            ("https://example.com/", ""),
            ("http://example.com/", "Content-Length: 1\r\nContent-Length: 2\r\n"),
            ("http://example.com/", "Content-Length: 1\r\nTransfer-Encoding: chunked\r\n"),
            ("http://example.com/", "Content-Length: -1\r\n"),
        ):
            with self.subTest(target=target, headers=headers):
                response = await self.request(
                    f"POST {target} HTTP/1.1\r\nHost: example.com\r\n{headers}\r\n".encode()
                )
                self.assertTrue(response.startswith(b"HTTP/1.1 400"))

    async def test_websocket_upgrade_and_echo(self):
        async def origin(reader, writer):
            head = await reader.readuntil(b"\r\n\r\n")
            self.assertIn(b"connection: Upgrade\r\n", head)
            self.assertIn(b"upgrade: websocket\r\n", head)
            writer.write(
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
            )
            await writer.drain()
            writer.write(await reader.readexactly(4))
            await writer.drain()

        port = await self.listen(origin)
        reader, writer = await self.connect()
        writer.write(
            f"GET http://127.0.0.1:{port}/ HTTP/1.1\r\nHost: ignored\r\n"
            "Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n".encode()
        )
        await writer.drain()
        self.assertTrue((await reader.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 101"))
        writer.write(b"ping")
        await writer.drain()
        self.assertEqual(await reader.readexactly(4), b"ping")

    async def test_websocket_rejection_uses_normal_framing(self):
        async def origin(reader, writer):
            await reader.readuntil(b"\r\n\r\n")
            writer.write(
                b"HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"2\r\nno\r\n0\r\n\r\n"
            )
            await writer.drain()

        port = await self.listen(origin)
        response = await self.request(
            f"GET http://127.0.0.1:{port}/ HTTP/1.1\r\nHost: ignored\r\n"
            "Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n".encode()
        )
        self.assertTrue(response.startswith(b"HTTP/1.1 403"))
        self.assertIn(b"Connection: close\r\n", response)
        self.assertTrue(response.endswith(b"2\r\nno\r\n0\r\n\r\n"))

    async def test_direct_connect_tunnel(self):
        async def origin(reader, writer):
            writer.write(await reader.readexactly(4))
            await writer.drain()

        port = await self.listen(origin)
        reader, writer = await self.connect()
        writer.write(f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n".encode())
        await writer.drain()
        self.assertEqual(
            await reader.readuntil(b"\r\n\r\n"),
            b"HTTP/1.1 200 Connection Established\r\n\r\n",
        )
        writer.write(b"ping")
        await writer.drain()
        self.assertEqual(await reader.readexactly(4), b"ping")

    async def test_budgeted_failover(self):
        reader = asyncio.StreamReader()
        writer = Mock(spec=asyncio.StreamWriter)
        attempts = []

        async def open_stream(host, port, scheme, proxy_host, proxy_port, **kwargs):
            attempts.append(proxy_port)
            if proxy_port == 1:
                await asyncio.Event().wait()
            return reader, writer, "http://backup:2"

        with (
            patch.object(proxy, "_open_upstream_stream", side_effect=open_stream),
            patch.object(proxy.random, "shuffle"),
            patch.object(proxy, "CONNECT_TIMEOUT", 0.1),
        ):
            result = await proxy._connect_with_failover(
                "example.com", 80, "http", [("stalled", 1), ("backup", 2)],
            )
        self.assertEqual(attempts, [1, 2])
        self.assertEqual(result[2], "http://backup:2")

    async def test_head_finishes_without_origin_close(self):
        async def origin(reader, writer):
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
            await writer.drain()
            await asyncio.Event().wait()

        port = await self.listen(origin)
        response = await self.request(
            f"HEAD http://127.0.0.1:{port}/ HTTP/1.1\r\n\r\n".encode()
        )
        self.assertTrue(response.startswith(b"HTTP/1.1 200"))
        self.assertTrue(response.endswith(b"\r\n\r\n"))

    async def test_http_upstream_uses_absolute_form_without_connect(self):
        received = []

        async def upstream(reader, writer):
            received.append(await reader.readuntil(b"\r\n\r\n"))
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            await writer.drain()

        port = await self.listen(upstream)
        with (
            patch.object(proxy, "get_route", AsyncMock(return_value="PROXY")),
            patch.object(proxy, "_upstream", {"http": [("127.0.0.1", port)]}),
        ):
            response = await self.request(
                b"GET http://example.com/path?q=1 HTTP/1.1\r\nHost: ignored\r\n\r\n"
            )
        self.assertTrue(response.endswith(b"\r\n\r\nok"))
        self.assertTrue(received[0].startswith(b"GET http://example.com/path?q=1 HTTP/1.1"))
        self.assertIn(b"host: example.com\r\n", received[0])

    async def test_http_upstream_connect_failover(self):
        async def upstream(reader, writer):
            head = await reader.readuntil(b"\r\n\r\n")
            self.assertTrue(head.startswith(b"CONNECT example.com:443 HTTP/1.1"))
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            writer.write(await reader.readexactly(4))
            await writer.drain()

        port = await self.listen(upstream)
        bad_server = await asyncio.start_server(upstream, "127.0.0.1", 0)
        bad_port = bad_server.sockets[0].getsockname()[1]
        bad_server.close()
        await bad_server.wait_closed()
        with (
            patch.object(proxy, "get_route", AsyncMock(return_value="PROXY")),
            patch.object(proxy, "_upstream", {
                "http": [("127.0.0.1", bad_port), ("127.0.0.1", port)],
            }),
            patch.object(proxy.random, "shuffle"),
        ):
            reader, writer = await self.connect()
            writer.write(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
            await writer.drain()
            self.assertTrue(
                (await reader.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 200")
            )
            writer.write(b"ping")
            await writer.drain()
            self.assertEqual(await reader.readexactly(4), b"ping")

    async def test_socks5_http_forwarding(self):
        async def socks(reader, writer):
            self.assertEqual(await reader.readexactly(3), b"\x05\x01\x00")
            writer.write(b"\x05\x00")
            await writer.drain()
            self.assertEqual(await reader.readexactly(4), b"\x05\x01\x00\x03")
            length = (await reader.readexactly(1))[0]
            self.assertEqual(await reader.readexactly(length), b"example.com")
            self.assertEqual(await reader.readexactly(2), b"\x00\x50")
            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            head = await reader.readuntil(b"\r\n\r\n")
            self.assertTrue(head.startswith(b"GET /path?q=1 HTTP/1.1"))
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            await writer.drain()

        port = await self.listen(socks)
        with (
            patch.object(proxy, "get_route", AsyncMock(return_value="PROXY")),
            patch.object(proxy, "_upstream", {"socks5": [("127.0.0.1", port)]}),
        ):
            response = await self.request(
                b"GET http://example.com/path?q=1 HTTP/1.1\r\n\r\n"
            )
        self.assertTrue(response.endswith(b"\r\n\r\nok"))

    async def test_chunked_response_with_standard_http_client(self):
        async def origin(reader, writer):
            await reader.readuntil(b"\r\n\r\n")
            writer.write(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"5\r\nhello\r\n0\r\n\r\n"
            )
            await writer.drain()

        port = await self.listen(origin)

        def fetch():
            connection = http.client.HTTPConnection("127.0.0.1", self.proxy_port, timeout=2)
            try:
                connection.request("GET", f"http://127.0.0.1:{port}/")
                response = connection.getresponse()
                return response.status, response.read(), response.will_close
            finally:
                connection.close()

        self.assertEqual(await asyncio.to_thread(fetch), (200, b"hello", True))

    async def test_incomplete_chunks_are_detectable_by_http_client(self):
        async def origin(reader, writer):
            await reader.readuntil(b"\r\n\r\n")
            writer.write(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"5\r\nhello"
            )
            await writer.drain()

        port = await self.listen(origin)

        def fetch():
            connection = http.client.HTTPConnection("127.0.0.1", self.proxy_port, timeout=2)
            try:
                connection.request("GET", f"http://127.0.0.1:{port}/")
                response = connection.getresponse()
                with self.assertRaises(http.client.IncompleteRead):
                    response.read()
            finally:
                connection.close()

        with self.assertLogs(proxy.logger, level="WARNING"):
            await asyncio.to_thread(fetch)

    async def test_invalid_chunked_upload_returns_bad_request(self):
        reader, writer = await self.connect()
        writer.write(
            b"POST http://example.com/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\n"
            b"\r\n5\r\nhelloXX"
        )
        writer.write_eof()
        with self.assertLogs(proxy.logger, level="WARNING"):
            response = await asyncio.wait_for(reader.read(), 2)
        self.assertTrue(response.startswith(b"HTTP/1.1 400"))

    async def test_ipv6_authority(self):
        self.assertEqual(proxy._host_header("::1", 80, 80), "[::1]")
        self.assertEqual(proxy._host_header("::1", 8080, 80), "[::1]:8080")


if __name__ == "__main__":
    unittest.main()
