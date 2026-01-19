"""Tests for trustchain/v2/tenants.py - Multi-tenancy support."""

import pytest
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from trustchain import TrustChain
from trustchain.v2.tenants import TenantManager, TenantInfo


class TestTenantInfo:
    """Test tenant info dataclass."""
    
    def test_create_info(self):
        info = TenantInfo(
            tenant_id="acme_corp",
            key_id="key-12345",
            created_at=1234567890.0
        )
        
        assert info.tenant_id == "acme_corp"
        assert info.key_id == "key-12345"


class TestTenantManager:
    """Test TenantManager class."""
    
    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as td:
            yield td
    
    def test_create_manager(self, temp_dir):
        manager = TenantManager(key_storage_dir=temp_dir)
        
        assert manager is not None
    
    def test_get_or_create_tenant(self, temp_dir):
        manager = TenantManager(key_storage_dir=temp_dir)
        
        tc = manager.get_or_create("tenant_1")
        
        assert tc is not None
        assert isinstance(tc, TrustChain)
    
    def test_same_tenant_returns_same_instance(self, temp_dir):
        manager = TenantManager(key_storage_dir=temp_dir)
        
        tc1 = manager.get_or_create("tenant_a")
        tc2 = manager.get_or_create("tenant_a")
        
        assert tc1 is tc2
    
    def test_different_tenants_different_instances(self, temp_dir):
        manager = TenantManager(key_storage_dir=temp_dir)
        
        tc1 = manager.get_or_create("tenant_x")
        tc2 = manager.get_or_create("tenant_y")
        
        assert tc1 is not tc2
    
    def test_different_tenants_different_keys(self, temp_dir):
        manager = TenantManager(key_storage_dir=temp_dir)
        
        tc1 = manager.get_or_create("company_a")
        tc2 = manager.get_or_create("company_b")
        
        key1 = tc1.get_key_id()
        key2 = tc2.get_key_id()
        
        assert key1 != key2
    
    def test_list_tenants(self, temp_dir):
        manager = TenantManager(key_storage_dir=temp_dir)
        
        manager.get_or_create("tenant_1")
        manager.get_or_create("tenant_2")
        manager.get_or_create("tenant_3")
        
        tenants = manager.list_tenants()
        
        assert len(tenants) == 3
        assert "tenant_1" in tenants
        assert "tenant_2" in tenants
        assert "tenant_3" in tenants
    
    def test_multiple_tenants(self, temp_dir):
        manager = TenantManager(key_storage_dir=temp_dir)
        
        manager.get_or_create("tenant_1")
        manager.get_or_create("tenant_2")
        manager.get_or_create("tenant_3")
        
        tenants = manager.list_tenants()
        
        assert len(tenants) >= 3


class TestTenantIsolation:
    """Test that tenants are properly isolated."""
    
    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as td:
            yield td
    
    def test_signatures_dont_verify_across_tenants(self, temp_dir):
        manager = TenantManager(key_storage_dir=temp_dir)
        
        tc_a = manager.get_or_create("tenant_a")
        tc_b = manager.get_or_create("tenant_b")
        
        # Sign with tenant A
        signed = tc_a._signer.sign("test", {"data": 1})
        
        # Verify with tenant A - should work
        assert tc_a._signer.verify(signed) is True
        
        # Verify with tenant B - should fail (different keys)
        assert tc_b._signer.verify(signed) is False
    
    def test_nonces_isolated_per_tenant(self, temp_dir):
        manager = TenantManager(key_storage_dir=temp_dir)
        
        tc_a = manager.get_or_create("tenant_a")
        tc_b = manager.get_or_create("tenant_b")
        
        # Same nonce should work for different tenants
        # (They have separate nonce stores)
        nonce = "shared_nonce_id"
        
        # This would require access to nonce storage internals
        # Just verify they have separate instances
        assert tc_a._nonce_storage is not tc_b._nonce_storage


class TestTenantPersistence:
    """Test tenant key persistence."""
    
    def test_keys_persist_after_restart(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            # First session
            manager1 = TenantManager(key_storage_dir=temp_dir)
            tc1 = manager1.get_or_create("persistent_tenant")
            key_id_1 = tc1.get_key_id()
            
            # Sign something
            signed = tc1._signer.sign("test", {"value": 42})
            
            # Second session (simulating restart)
            manager2 = TenantManager(key_storage_dir=temp_dir)
            tc2 = manager2.get_or_create("persistent_tenant")
            key_id_2 = tc2.get_key_id()
            
            # Should have same key
            assert key_id_1 == key_id_2
            
            # Should be able to verify old signature
            assert tc2._signer.verify(signed) is True
