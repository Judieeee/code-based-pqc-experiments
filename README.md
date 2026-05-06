# Code-Based Post-Quantum Cryptography 实验

基于 [liboqs](https://github.com/open-quantum-safe/liboqs) 的 Code-Based 后量子密码学（PQC）实验项目。本实验聚焦于基于编码理论的抗量子密钥封装机制（KEM），包括 **BIKE**、**Classic McEliece** 和 **HQC** 三种算法族。

## 实验概览

| 实验 | 文件 | 研究目标 | 核心指标 |
|------|------|---------|---------|
| 实验1 | `exp1.py` | 算法性能基准测试 | 密钥生成、封装、解封装时间 |
| 实验2 | `exp2.py` | 通信开销分析 | 公钥/密文大小、TLS握手额外开销 |
| 实验3 | `exp3.py` | 混合密钥交换 | ECDH + Code-Based KEM 组合安全性 |
| 实验4 | `exp4.py` | 侧信道时间分析 | 变异系数(CV)、时间分布特征 |

## 背景知识

### 什么是 Code-Based 密码学？

Code-Based 密码学的安全性基于**纠错码译码问题的困难性**。给定一个带有随机错误的线性码，在没有私钥（译码 trapdoor）的情况下，恢复原始消息是 NP-难的。

### 三种主要 Code-Based KEM

| 算法族 | 底层码结构 | 特点 | NIST 状态 |
|--------|-----------|------|----------|
| **BIKE** | QC-MDPC 码 | 公钥较小，性能均衡 | Round 4 候选 |
| **Classic McEliece** | Goppa 码 | 公钥极大(255KB~1.3MB)，安全性最保守 | Round 4 候选 |
| **HQC** | Reed-Muller + Reed-Solomon 码 | 设计更模块化 | 2025 年新入选标准化备选 |

## 环境要求

### 系统依赖

- CMake ≥ 3.10
- GCC 或 Clang（支持 C11）
- OpenSSL ≥ 1.1.1（供 liboqs 使用对称加密原语）
- Python 3.8+

### 安装 liboqs C库
### python依赖

```bash
pip install liboqs-python cryptography numpy
