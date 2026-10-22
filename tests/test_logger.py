"""
Unit tests for src/logger.py: Ring-buffer logger, rotating file logging, and WebSocket broadcaster.
"""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
import pytest
from src.logger import RingBufferLogger, WebSocketBroadcaster, setup_logger


def test_ring_buffer_capacity_eviction(tmp_path: Path):
    """Verify that buffer size is hard-capped at capacity and evicts oldest entries."""
    logger = RingBufferLogger(capacity=10)
    for i in range(15):
        logger.log("INFO", f"Message {i}")

    assert len(logger.buffer) == 10
    recent = logger.get_recent_logs(10)
    assert len(recent) == 10
    assert "Message 5" in recent[0]
    assert "Message 14" in recent[-1]


def test_logger_file_persistence(tmp_path: Path):
    """Verify logs are written to the specified log file."""
    log_file = tmp_path / "bughunter.log"
    logger = RingBufferLogger(capacity=100, log_file=log_file)
    logger.log("WARN", "Warning event occurred")
    logger.log("ERROR", "Error event occurred")

    assert log_file.exists()
    content = log_file.read_text(encoding="utf-8")
    assert "[WARN] Warning event occurred" in content
    assert "[ERROR] Error event occurred" in content


def test_logger_subscribers():
    """Verify custom subscriber callbacks receive log entries."""
    logger = RingBufferLogger(capacity=50)
    received = []
    logger.add_subscriber(received.append)

    logger.log("INFO", "Subscription test line")
    assert len(received) == 1
    assert "Subscription test line" in received[0]


def test_websocket_broadcaster_connect_and_broadcast():
    """Verify WebSocketBroadcaster connects, replays logs, broadcasts, and handles disconnects."""
    async def _run():
        broadcaster = WebSocketBroadcaster()
        mock_ws1 = AsyncMock()
        mock_ws2 = AsyncMock()

        # Test connect with replay
        initial_logs = ["Log 1", "Log 2"]
        await broadcaster.connect(mock_ws1, initial_logs=initial_logs)
        assert mock_ws1 in broadcaster.connections
        assert mock_ws1.send_text.call_count == 2

        # Connect second socket
        await broadcaster.connect(mock_ws2)
        assert len(broadcaster.connections) == 2

        # Broadcast to both
        await broadcaster.broadcast("Live log message")
        mock_ws1.send_text.assert_called_with("Live log message")
        mock_ws2.send_text.assert_called_with("Live log message")

        # Simulate disconnect on mock_ws1
        mock_ws1.send_text.side_effect = ConnectionResetError("Client closed")
        await broadcaster.broadcast("Second live log message")
        assert mock_ws1 not in broadcaster.connections
        assert mock_ws2 in broadcaster.connections

    asyncio.run(_run())


def test_setup_logger_integration(tmp_path: Path):
    """Verify standard python logging integrates with RingBufferLogHandler."""
    log_file = tmp_path / "sys.log"
    py_logger, ring_logger, broadcaster = setup_logger(
        name="test_integration",
        log_file=log_file,
        capacity=20
    )

    py_logger.info("Standard python logging message")
    recent = ring_logger.get_recent_logs(5)
    assert len(recent) == 1
    assert "Standard python logging message" in recent[0]


def test_logger_rotating_file_handler_delegation(tmp_path: Path):
    """Verify RingBufferLogger delegates to RotatingFileHandler with 10MB limit and 5 backups."""
    from logging.handlers import RotatingFileHandler
    log_file = tmp_path / "delegated.log"
    logger = RingBufferLogger(capacity=10, log_file=log_file)
    assert isinstance(logger._file_handler, RotatingFileHandler)
    assert logger._file_handler.maxBytes == 10 * 1024 * 1024
    assert logger._file_handler.backupCount == 5
    logger.log("INFO", "Delegated write test")
    assert log_file.exists()
    assert "Delegated write test" in log_file.read_text(encoding="utf-8")


def test_setup_logger_reuses_file_handler_without_duplicate(tmp_path: Path):
    """Verify setup_logger reuses ring_logger._file_handler to prevent dual handle locks."""
    from logging.handlers import RotatingFileHandler

    log_file = tmp_path / "single_handle.log"
    logger, ring_logger, _ = setup_logger(name="test_single_handle", log_file=log_file)

    # Verify logger has exactly ring_logger._file_handler and not a separate instance
    file_handlers = [h for h in logger.handlers if isinstance(h, RotatingFileHandler)]
    assert len(file_handlers) == 1
    assert file_handlers[0] is ring_logger._file_handler

    logger.info("Test from logger")
    ring_logger.log("INFO", "Test from ring_logger")
    ring_logger.close()


