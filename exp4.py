"""
实验4：Code-Based KEM 侧信道时间分析
分析密钥生成、封装、解封装的时间分布，寻找潜在的时间侧信道
"""

import oqs
import time
import numpy as np
import json
import os

def collect_timing_samples(alg_name: str, samples: int = 1000) -> dict:
    """收集大量时间样本进行统计分析"""
    
    keygen_times = []
    encaps_times = []
    decaps_times = []
    
    print(f"  收集 {alg_name} 的 {samples} 个时间样本...")
    
    for i in range(samples):
        if i % 100 == 0:
            print(f"    {i}/{samples}...")
        
        # 密钥生成
        t0 = time.perf_counter_ns()
        with oqs.KeyEncapsulation(alg_name) as kem:
            pk = kem.generate_keypair()
            t1 = time.perf_counter_ns()
            keygen_times.append(t1 - t0)
            
            # 封装
            t2 = time.perf_counter_ns()
            ct, ss = kem.encap_secret(pk)
            t3 = time.perf_counter_ns()
            encaps_times.append(t3 - t2)
        
        # 解封装（需要新实例）
        with oqs.KeyEncapsulation(alg_name) as kem:
            pk = kem.generate_keypair()
            ct, _ = kem.encap_secret(pk)
            
            t4 = time.perf_counter_ns()
            ss = kem.decap_secret(ct)
            t5 = time.perf_counter_ns()
            decaps_times.append(t5 - t4)
    
    # 统计分析
    keygen_arr = np.array(keygen_times) / 1e6  # 转换为毫秒
    encaps_arr = np.array(encaps_times) / 1e6
    decaps_arr = np.array(decaps_times) / 1e6
    
    return {
        "algorithm": alg_name,
        "samples": samples,
        "keygen": {
            "mean_ms": float(np.mean(keygen_arr)),
            "std_ms": float(np.std(keygen_arr)),
            "min_ms": float(np.min(keygen_arr)),
            "max_ms": float(np.max(keygen_arr)),
            "median_ms": float(np.median(keygen_arr)),
            "p99_ms": float(np.percentile(keygen_arr, 99)),
        },
        "encaps": {
            "mean_ms": float(np.mean(encaps_arr)),
            "std_ms": float(np.std(encaps_arr)),
            "min_ms": float(np.min(encaps_arr)),
            "max_ms": float(np.max(encaps_arr)),
            "median_ms": float(np.median(encaps_arr)),
            "p99_ms": float(np.percentile(encaps_arr, 99)),
        },
        "decaps": {
            "mean_ms": float(np.mean(decaps_arr)),
            "std_ms": float(np.std(decaps_arr)),
            "min_ms": float(np.min(decaps_arr)),
            "max_ms": float(np.max(decaps_arr)),
            "median_ms": float(np.median(decaps_arr)),
            "p99_ms": float(np.percentile(decaps_arr, 99)),
        },
        # 变异系数（CV）= std/mean，衡量相对波动
        "keygen_cv": float(np.std(keygen_arr) / np.mean(keygen_arr)),
        "encaps_cv": float(np.std(encaps_arr) / np.mean(encaps_arr)),
        "decaps_cv": float(np.std(decaps_arr) / np.mean(decaps_arr)),
    }


def main():
    print("Code-Based KEM 时间侧信道分析")
    print("=" * 60)
    
    code_based = [
        k for k in oqs.get_enabled_kem_mechanisms()
        if any(name in k for name in ["BIKE", "McEliece", "HQC"])
    ]
    
    all_results = []
    for alg in code_based[:6]:  # 限制测试数量，避免时间过长
        result = collect_timing_samples(alg, samples=500)
        all_results.append(result)
    
    # 打印结果
    print("\n时间分布分析结果:")
    print("-" * 80)
    
    for r in all_results:
        print(f"\n{r['algorithm']}:")
        print(f"  密钥生成: {r['keygen']['mean_ms']:.2f}±{r['keygen']['std_ms']:.2f} ms (CV={r['keygen_cv']:.3f})")
        print(f"  封装:     {r['encaps']['mean_ms']:.2f}±{r['encaps']['std_ms']:.2f} ms (CV={r['encaps_cv']:.3f})")
        print(f"  解封装:   {r['decaps']['mean_ms']:.2f}±{r['decaps']['std_ms']:.2f} ms (CV={r['decaps_cv']:.3f})")
        
        # 高 CV 可能暗示时间侧信道
        if r['keygen_cv'] > 0.1:
            print(f"  ⚠️  密钥生成变异系数较高，可能存在时间侧信道")
        if r['encaps_cv'] > 0.1:
            print(f"  ⚠️  封装修正系数较高，可能存在时间侧信道")
    
    # 保存结果
    os.makedirs("../results", exist_ok=True)
    with open("../results/timing_analysis.json", "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\n结果已保存")


if __name__ == "__main__":
    main()