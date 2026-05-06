"""
实验1：Code-Based KEM 算法性能基准测试
对比 BIKE, Classic McEliece, HQC 在三个 NIST 安全级别的表现
"""

import oqs
import time
import sys
from typing import List, Tuple, Dict

# 选择要测试的 code-based KEM 算法
CODE_BASED_KEMS = {
    "BIKE": ["BIKE-L1", "BIKE-L3", "BIKE-L5"],
    "Classic-McEliece": [
        "Classic-McEliece-348864",
        "Classic-McEliece-460896",
        "Classic-McEliece-6688128",
        "Classic-McEliece-6960119",
        "Classic-McEliece-8192128",
    ],
    "HQC-128": ["HQC-128"],
}

# 如果 HQC-128 不在列表中，说明你可能需要启用 HQC
# 可以检查所有可用的 code-based 算法
def discover_code_based_kems() -> List[str]:
    """自动发现所有可用的 code-based KEM 算法"""
    all_kems = oqs.get_enabled_kem_mechanisms()
    code_based = []
    for kem in all_kems:
        if any(name in kem for name in ["BIKE", "McEliece", "HQC"]):
            code_based.append(kem)
    return sorted(code_based)


def benchmark_kem(alg_name: str, iterations: int = 100) -> Dict:
    """
    对单个 KEM 算法进行性能基准测试
    
    返回:
        dict: 包含性能指标的字典
    """
    print(f"  测试 {alg_name}...", end=" ", flush=True)
    
    try:
        # 获取算法详情
        with oqs.KeyEncapsulation(alg_name) as kem:
            details = {
                "name": alg_name,
                "claimed_nist_level": kem.details["claimed_nist_level"],
                "length_public_key": kem.details["length_public_key"],
                "length_secret_key": kem.details["length_secret_key"],
                "length_ciphertext": kem.details["length_ciphertext"],
                "length_shared_secret": kem.details["length_shared_secret"],
            }
        
        # 性能测试
        keygen_times = []
        encaps_times = []
        decaps_times = []
        
        for _ in range(iterations):
            # 密钥生成
            start = time.perf_counter()
            with oqs.KeyEncapsulation(alg_name) as client:
                pk = client.generate_keypair()
            keygen_times.append(time.perf_counter() - start)
            
            # 封装
            with oqs.KeyEncapsulation(alg_name) as client:
                pk = client.generate_keypair()
                
                start = time.perf_counter()
                ct, ss_alice = client.encap_secret(pk)
                encaps_times.append(time.perf_counter() - start)
            
            # 解封装（需要新的实例模拟 Bob）
            with oqs.KeyEncapsulation(alg_name) as server:
                # 先设置 Bob 的密钥（实际场景中 Bob 自己生成密钥对）
                pk_bob = server.generate_keypair()
                ct_bob, ss_bob_alice = server.encap_secret(pk_bob)
                
                start = time.perf_counter()
                ss_bob = server.decap_secret(ct_bob)
                decaps_times.append(time.perf_counter() - start)
        
        # 计算统计数据
        import statistics
        details.update({
            "keygen_mean_ms": statistics.mean(keygen_times) * 1000,
            "keygen_std_ms": statistics.stdev(keygen_times) * 1000,
            "encaps_mean_ms": statistics.mean(encaps_times) * 1000,
            "encaps_std_ms": statistics.stdev(encaps_times) * 1000,
            "decaps_mean_ms": statistics.mean(decaps_times) * 1000,
            "decaps_std_ms": statistics.stdev(decaps_times) * 1000,
        })
        
        print("✓")
        return details
        
    except oqs.MechanismNotEnabledError:
        print(f"✗ (未启用)")
        return None
    except Exception as e:
        print(f"✗ ({e})")
        return None


def print_results(results: List[Dict]):
    """打印格式化的性能对比表"""
    print("\n" + "=" * 120)
    print("Code-Based KEM 算法性能对比")
    print("=" * 120)
    
    # 表头
    header = f"{'算法名称':<35} {'级别':<5} {'|PK|':<8} {'|SK|':<8} {'|CT|':<8} {'密钥生成(ms)':<16} {'封装(ms)':<16} {'解封装(ms)':<16}"
    print(header)
    print("-" * 120)
    
    for r in results:
        if r is None:
            continue
        line = (
            f"{r['name']:<35} "
            f"{r['claimed_nist_level']:<5} "
            f"{r['length_public_key']:<8} "
            f"{r['length_secret_key']:<8} "
            f"{r['length_ciphertext']:<8} "
            f"{r['keygen_mean_ms']:>7.2f}±{r['keygen_std_ms']:<7.2f} "
            f"{r['encaps_mean_ms']:>7.2f}±{r['encaps_std_ms']:<7.2f} "
            f"{r['decaps_mean_ms']:>7.2f}±{r['decaps_std_ms']:<7.2f}"
        )
        print(line)
    
    print("-" * 120)
    print("注: |PK|=公钥长度(字节), |SK|=私钥长度(字节), |CT|=密文长度(字节)")
    print("    性能数据为 " + str(100) + " 次迭代的平均值±标准差")


def main():
    print("🔬 Code-Based PQC 实验1: KEM 性能基准测试")
    print("=" * 50)
    
    # 发现可用的 code-based KEM
    print("\n发现以下 Code-Based KEM 算法:")
    available = discover_code_based_kems()
    for alg in available:
        print(f"  • {alg}")
    
    print(f"\n开始性能测试 (每个算法测试 100 次)...")
    
    results = []
    for alg in available:
        result = benchmark_kem(alg, iterations=100)
        if result:
            results.append(result)
    
    print_results(results)
    
    # 保存结果到文件
    import json
    output_file = "../results/kem_benchmark.json"
    import os
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n结果已保存到 {output_file}")


if __name__ == "__main__":
    main()
