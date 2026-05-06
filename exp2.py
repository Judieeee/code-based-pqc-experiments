"""
实验2：Code-Based KEM 通信开销分析
模拟 TLS 握手场景，计算使用不同 KEM 时的额外带宽开销
"""

import oqs
import json
import os

def analyze_communication_overhead():
    """分析各算法在 TLS 握手中的通信开销"""
    
    code_based_kems = [
        k for k in oqs.get_enabled_kem_mechanisms()
        if any(name in k for name in ["BIKE", "McEliece", "HQC"])
    ]
    
    # 传统算法对比基准
    traditional = {
        "RSA-2048": {"pk": 256, "ct": 256},
        "ECDH-P256": {"pk": 32, "ct": 0},  # ECDH 不需要额外密文
    }
    
    results = []
    
    for alg in sorted(code_based_kems):
        with oqs.KeyEncapsulation(alg) as kem:
            details = kem.details
            pk_size = details["length_public_key"]
            ct_size = details["length_ciphertext"]
            
            # TLS 1.3 握手额外开销估算:
            # - 证书中增加的公钥大小
            # - ClientHello 扩展或 ServerHello 中的额外数据
            overhead = {
                "algorithm": alg,
                "nist_level": details["claimed_nist_level"],
                "public_key_bytes": pk_size,
                "ciphertext_bytes": ct_size,
                "total_extra_bytes": pk_size + ct_size,
                "vs_rsa_2048_ratio": round((pk_size + ct_size) / (256 + 256), 2),
                "vs_ecdh_p256_ratio": round((pk_size + ct_size) / (32), 2),
            }
            results.append(overhead)
    
    # 打印结果
    print("\n通信开销分析 (TLS 握手场景)")
    print("=" * 100)
    print(f"{'算法':<35} {'NIST级别':<8} {'公钥(B)':<10} {'密文(B)':<10} {'总额外(B)':<12} {'vs RSA':<10} {'vs ECDH':<10}")
    print("-" * 100)
    
    for r in results:
        print(
            f"{r['algorithm']:<35} "
            f"{r['nist_level']:<8} "
            f"{r['public_key_bytes']:<10} "
            f"{r['ciphertext_bytes']:<10} "
            f"{r['total_extra_bytes']:<12} "
            f"{r['vs_rsa_2048_ratio']:<10.1f}x "
            f"{r['vs_ecdh_p256_ratio']:<10.1f}x"
        )
    
    print("-" * 100)
    print("注: 传统 RSA 公钥~256B, ECDH 公钥~32B")
    
    # 找出开销最小的 code-based 算法
    best = min(results, key=lambda x: x["total_extra_bytes"])
    print(f"\n通信开销最小的 Code-Based 算法: {best['algorithm']}")
    print(f"  总额外字节: {best['total_extra_bytes']} B")
    
    return results

if __name__ == "__main__":
    os.makedirs("../results", exist_ok=True)
    results = analyze_communication_overhead()
    with open("../results/communication_overhead.json", "w") as f:
        json.dump(results, f, indent=2)