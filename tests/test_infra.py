"""
Infrastructure and Deployment Configuration Tests for AutoBugHunter 24/7.
"""

from pathlib import Path


def test_docker_compose_memory_limit_is_20g():
    """Verify docker-compose.yml specifies 20G container memory limit for Oracle ARM64."""
    compose_path = Path("docker-compose.yml")
    assert compose_path.exists(), "docker-compose.yml must exist at project root"
    content = compose_path.read_text(encoding="utf-8")
    assert "memory: 20G" in content, "Expected 'memory: 20G' in docker-compose.yml deploy limits"
    assert "memory: 1800M" not in content, "'memory: 1800M' must be updated to 20G"
