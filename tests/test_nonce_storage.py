"""Tests for trustchain/v2/nonce_storage.py - Nonce storage backends."""

import pytest
import time

from trustchain.v2.nonce_storage import MemoryNonceStorage, create_nonce_storage


class TestMemoryNonceStorage:
    """Test in-memory nonce storage."""
    
    def test_create_storage(self):
        storage = MemoryNonceStorage()
        assert storage is not None
    
    def test_create_with_maxlen(self):
        storage = MemoryNonceStorage(maxlen=100)
        assert storage is not None
    
    def test_check_and_add_new_nonce(self):
        storage = MemoryNonceStorage()
        result = storage.check_and_add("nonce123")
        
        assert result is True  # New nonce added
    
    def test_check_and_add_duplicate(self):
        storage = MemoryNonceStorage()
        storage.check_and_add("nonce456")
        
        result = storage.check_and_add("nonce456")
        
        assert result is False  # Duplicate detected
    
    def test_contains_existing_nonce(self):
        storage = MemoryNonceStorage()
        storage.check_and_add("test_nonce")
        
        assert storage.contains("test_nonce") is True
    
    def test_contains_unknown_nonce(self):
        storage = MemoryNonceStorage()
        
        assert storage.contains("unknown") is False
    
    def test_multiple_nonces(self):
        storage = MemoryNonceStorage()
        
        for i in range(100):
            result = storage.check_and_add(f"nonce_{i}")
            assert result is True
        
        for i in range(100):
            assert storage.contains(f"nonce_{i}") is True
    
    def test_clear(self):
        storage = MemoryNonceStorage()
        storage.check_and_add("nonce1")
        storage.check_and_add("nonce2")
        
        storage.clear()
        
        assert storage.contains("nonce1") is False
        assert storage.contains("nonce2") is False
    
    def test_ttl_expiry(self):
        storage = MemoryNonceStorage()
        storage.check_and_add("expiring_nonce", ttl=1)
        
        # Should exist immediately
        assert storage.contains("expiring_nonce") is True
        
        # Wait for expiry
        time.sleep(1.1)
        
        # After expiry, should not contain
        assert storage.contains("expiring_nonce") is False
    
    def test_maxlen_capacity(self):
        storage = MemoryNonceStorage(maxlen=5)
        
        # Add 5 nonces
        for i in range(5):
            result = storage.check_and_add(f"nonce_{i}")
            assert result is True
        
        # All 5 should exist
        for i in range(5):
            assert storage.contains(f"nonce_{i}") is True
        
        # 6th nonce should also work (deque handles eviction)
        result = storage.check_and_add("nonce_5")
        assert result is True


class TestCreateNonceStorage:
    """Test factory function."""
    
    def test_create_memory_storage(self):
        storage = create_nonce_storage("memory")
        assert isinstance(storage, MemoryNonceStorage)
    
    def test_create_memory_with_kwargs(self):
        storage = create_nonce_storage("memory", maxlen=500)
        assert storage is not None
    
    def test_create_redis_without_url_raises(self):
        with pytest.raises(ValueError):
            create_nonce_storage("redis")
    
    def test_create_unknown_backend_raises(self):
        with pytest.raises(ValueError):
            create_nonce_storage("unknown")
