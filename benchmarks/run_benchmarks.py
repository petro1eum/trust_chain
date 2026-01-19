#!/usr/bin/env python3
"""TrustChain Performance Benchmarks.

Measures:
- Sign latency
- Verify latency
- Throughput (ops/sec)
- Memory overhead

Usage:
    python benchmarks/run_benchmarks.py
"""

import time
import statistics
import json
from dataclasses import dataclass
from typing import List, Dict

from trustchain import TrustChain


@dataclass
class BenchmarkResult:
    """Result of a benchmark run."""
    name: str
    iterations: int
    total_time: float
    mean_latency_ms: float
    median_latency_ms: float
    p99_latency_ms: float
    throughput_ops_sec: float


def benchmark_sign(tc: TrustChain, iterations: int = 1000) -> BenchmarkResult:
    """Benchmark sign operation."""
    latencies = []
    
    for i in range(iterations):
        data = {"test": f"data_{i}", "value": i * 100}
        
        start = time.perf_counter()
        tc._signer.sign(f"tool_{i % 10}", data)
        end = time.perf_counter()
        
        latencies.append((end - start) * 1000)  # Convert to ms
    
    total_time = sum(latencies)
    
    return BenchmarkResult(
        name="Sign",
        iterations=iterations,
        total_time=total_time / 1000,  # Total in seconds
        mean_latency_ms=statistics.mean(latencies),
        median_latency_ms=statistics.median(latencies),
        p99_latency_ms=sorted(latencies)[int(iterations * 0.99)],
        throughput_ops_sec=iterations / (total_time / 1000)
    )


def benchmark_verify(tc: TrustChain, iterations: int = 1000) -> BenchmarkResult:
    """Benchmark verify operation."""
    # Pre-sign responses
    responses = []
    for i in range(iterations):
        data = {"test": f"data_{i}", "value": i * 100}
        resp = tc._signer.sign(f"tool_{i % 10}", data)
        responses.append(resp)
    
    latencies = []
    
    for resp in responses:
        start = time.perf_counter()
        tc._signer.verify(resp)
        end = time.perf_counter()
        
        latencies.append((end - start) * 1000)
    
    total_time = sum(latencies)
    
    return BenchmarkResult(
        name="Verify",
        iterations=iterations,
        total_time=total_time / 1000,
        mean_latency_ms=statistics.mean(latencies),
        median_latency_ms=statistics.median(latencies),
        p99_latency_ms=sorted(latencies)[int(iterations * 0.99)],
        throughput_ops_sec=iterations / (total_time / 1000)
    )


def benchmark_chain_sign(tc: TrustChain, chain_length: int = 100) -> BenchmarkResult:
    """Benchmark signing a chain of operations."""
    latencies = []
    parent_sig = None
    
    start_total = time.perf_counter()
    
    for i in range(chain_length):
        data = {"step": i, "action": f"action_{i}"}
        
        start = time.perf_counter()
        resp = tc._signer.sign("chain_tool", data, parent_signature=parent_sig)
        end = time.perf_counter()
        
        latencies.append((end - start) * 1000)
        parent_sig = resp.signature
    
    end_total = time.perf_counter()
    total_time = (end_total - start_total)
    
    return BenchmarkResult(
        name="Chain Sign",
        iterations=chain_length,
        total_time=total_time,
        mean_latency_ms=statistics.mean(latencies),
        median_latency_ms=statistics.median(latencies),
        p99_latency_ms=sorted(latencies)[int(chain_length * 0.99)],
        throughput_ops_sec=chain_length / total_time
    )


def benchmark_chain_verify(tc: TrustChain, chain_length: int = 100) -> BenchmarkResult:
    """Benchmark verifying a chain."""
    # Build chain
    chain = []
    parent_sig = None
    
    for i in range(chain_length):
        data = {"step": i, "action": f"action_{i}"}
        resp = tc._signer.sign("chain_tool", data, parent_signature=parent_sig)
        chain.append(resp)
        parent_sig = resp.signature
    
    # Benchmark verification
    start = time.perf_counter()
    result = tc.verify_chain(chain)
    end = time.perf_counter()
    
    latency = (end - start) * 1000
    
    return BenchmarkResult(
        name=f"Chain Verify ({chain_length} items)",
        iterations=1,
        total_time=latency / 1000,
        mean_latency_ms=latency,
        median_latency_ms=latency,
        p99_latency_ms=latency,
        throughput_ops_sec=chain_length / (latency / 1000)
    )


def benchmark_merkle(iterations: int = 100) -> BenchmarkResult:
    """Benchmark Merkle tree operations."""
    from trustchain.v2.merkle import MerkleTree, verify_proof
    
    # Create 100-page document
    pages = [f"Page {i}: " + "x" * 1000 for i in range(100)]
    
    latencies = []
    
    for _ in range(iterations):
        start = time.perf_counter()
        
        # Build tree
        tree = MerkleTree.from_chunks(pages)
        
        # Get proof for random page
        proof = tree.get_proof(42)
        
        # Verify proof
        verify_proof(pages[42], proof, tree.root)
        
        end = time.perf_counter()
        latencies.append((end - start) * 1000)
    
    total_time = sum(latencies) / 1000
    
    return BenchmarkResult(
        name="Merkle (100 pages)",
        iterations=iterations,
        total_time=total_time,
        mean_latency_ms=statistics.mean(latencies),
        median_latency_ms=statistics.median(latencies),
        p99_latency_ms=sorted(latencies)[int(iterations * 0.99)],
        throughput_ops_sec=iterations / total_time
    )


def measure_signature_size(tc: TrustChain) -> Dict:
    """Measure storage overhead of signatures."""
    import sys
    
    # Sign data of different sizes
    sizes = {}
    
    for data_size in [10, 100, 1000, 10000]:
        data = {"content": "x" * data_size}
        resp = tc._signer.sign("size_test", data)
        
        # Measure signature-related overhead
        sig_bytes = len(resp.signature.encode())
        nonce_bytes = len(resp.nonce.encode()) if resp.nonce else 0
        
        sizes[f"{data_size}_bytes_data"] = {
            "signature_bytes": sig_bytes,
            "nonce_bytes": nonce_bytes,
            "total_overhead_bytes": sig_bytes + nonce_bytes,
        }
    
    return sizes


def run_all_benchmarks() -> Dict:
    """Run all benchmarks and return results."""
    print("🔐 TrustChain Performance Benchmarks")
    print("=" * 50)
    
    tc = TrustChain()
    results = {}
    
    # Sign benchmark
    print("\n⏱️  Benchmarking Sign operation...")
    sign_result = benchmark_sign(tc, 1000)
    results["sign"] = sign_result
    print(f"   Mean latency: {sign_result.mean_latency_ms:.3f} ms")
    print(f"   P99 latency:  {sign_result.p99_latency_ms:.3f} ms")
    print(f"   Throughput:   {sign_result.throughput_ops_sec:.0f} ops/sec")
    
    # Verify benchmark
    print("\n⏱️  Benchmarking Verify operation...")
    verify_result = benchmark_verify(tc, 1000)
    results["verify"] = verify_result
    print(f"   Mean latency: {verify_result.mean_latency_ms:.3f} ms")
    print(f"   P99 latency:  {verify_result.p99_latency_ms:.3f} ms")
    print(f"   Throughput:   {verify_result.throughput_ops_sec:.0f} ops/sec")
    
    # Chain sign benchmark
    print("\n⏱️  Benchmarking Chain Sign (100 items)...")
    chain_sign_result = benchmark_chain_sign(tc, 100)
    results["chain_sign"] = chain_sign_result
    print(f"   Mean latency: {chain_sign_result.mean_latency_ms:.3f} ms")
    print(f"   Total time:   {chain_sign_result.total_time:.3f} s")
    
    # Chain verify benchmark
    print("\n⏱️  Benchmarking Chain Verify (100 items)...")
    chain_verify_result = benchmark_chain_verify(tc, 100)
    results["chain_verify"] = chain_verify_result
    print(f"   Total time:   {chain_verify_result.mean_latency_ms:.1f} ms")
    print(f"   Per-item:     {chain_verify_result.mean_latency_ms / 100:.3f} ms")
    
    # Merkle benchmark
    print("\n⏱️  Benchmarking Merkle Tree (100 pages)...")
    merkle_result = benchmark_merkle(100)
    results["merkle"] = merkle_result
    print(f"   Mean latency: {merkle_result.mean_latency_ms:.3f} ms")
    print(f"   Throughput:   {merkle_result.throughput_ops_sec:.0f} ops/sec")
    
    # Storage overhead
    print("\n📦 Measuring signature storage overhead...")
    storage = measure_signature_size(tc)
    results["storage"] = storage
    print(f"   Signature size: ~{storage['100_bytes_data']['signature_bytes']} bytes")
    print(f"   Nonce size:     ~{storage['100_bytes_data']['nonce_bytes']} bytes")
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 SUMMARY")
    print("=" * 50)
    print(f"✅ Sign latency:     {sign_result.mean_latency_ms:.2f} ms (target: <2ms)")
    print(f"✅ Verify latency:   {verify_result.mean_latency_ms:.2f} ms (target: <2ms)")
    print(f"✅ Throughput:       {sign_result.throughput_ops_sec:.0f}+ ops/sec (target: 10k+)")
    print(f"✅ Storage overhead: {storage['100_bytes_data']['total_overhead_bytes']} bytes/op")
    
    return results


def save_results(results: Dict, filepath: str = "benchmarks/results.json"):
    """Save benchmark results to JSON."""
    # Convert dataclasses to dicts
    output = {}
    for key, value in results.items():
        if isinstance(value, BenchmarkResult):
            output[key] = {
                "name": value.name,
                "iterations": value.iterations,
                "total_time_sec": value.total_time,
                "mean_latency_ms": value.mean_latency_ms,
                "median_latency_ms": value.median_latency_ms,
                "p99_latency_ms": value.p99_latency_ms,
                "throughput_ops_sec": value.throughput_ops_sec,
            }
        else:
            output[key] = value
    
    with open(filepath, "w") as f:
        json.dump(output, f, indent=2)
    
    print(f"\n💾 Results saved to {filepath}")


if __name__ == "__main__":
    results = run_all_benchmarks()
    save_results(results)
