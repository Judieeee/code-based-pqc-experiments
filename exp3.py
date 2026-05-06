"""
实验3：混合密钥交换 - ECDH + Code-Based KEM
结合传统椭圆曲线和抗量子 code-based KEM
"""

import oqs
import hashlib
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class HybridKeyExchange:
    """
    混合密钥交换: ECDH (传统) + Code-Based KEM (抗量子)
    只要其中一个安全，整体就安全
    """
    
    def __init__(self, pq_algorithm: str = "BIKE-L1"):
        self.pq_alg = pq_algorithm
        # 生成 ECDH 密钥对
        self.ecdh_private = ec.generate_private_key(
            ec.SECP256R1(), default_backend()
        )
        self.ecdh_public = self.ecdh_private.public_key()
        
        # 初始化 PQC KEM
        self.pqc_kem = oqs.KeyEncapsulation(pq_algorithm)
        self.pqc_public = self.pqc_kem.generate_keypair()
    
    def get_public_material(self) -> dict:
        """返回需要发送给对方的公钥材料"""
        # 序列化 ECDH 公钥
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat
        )
        ecdh_pub_bytes = self.ecdh_public.public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )
        
        return {
            "ecdh_public": ecdh_pub_bytes,
            "pqc_public": self.pqc_public,
        }
    
    def encapsulate(self, peer_ecdh_public_bytes: bytes, peer_pqc_public: bytes) -> bytes:
        """使用对方公钥生成共享密钥"""
        # 1. ECDH 部分
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat
        )
        peer_ecdh_public = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), peer_ecdh_public_bytes
        )
        ecdh_shared = self.ecdh_private.exchange(ec.ECDH(), peer_ecdh_public)
        
        # 2. PQC KEM 部分
        ct, pqc_shared = self.pqc_kem.encap_secret(peer_pqc_public)
        
        # 3. 组合两个共享密钥
        combined = ecdh_shared + pqc_shared
        hybrid_shared = hashlib.sha3_256(combined).digest()
        
        # 保存密文以便传输
        self.ciphertext = ct
        
        return hybrid_shared
    
    def decapsulate(self, ciphertext: bytes, peer_ecdh_public_bytes: bytes) -> bytes:
        """解封装对方发来的混合密钥"""
        # ECDH
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat
        )
        peer_ecdh_public = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), peer_ecdh_public_bytes
        )
        ecdh_shared = self.ecdh_private.exchange(ec.ECDH(), peer_ecdh_public)
        
        # PQC KEM
        pqc_shared = self.pqc_kem.decap_secret(ciphertext)
        
        # 组合
        combined = ecdh_shared + pqc_shared
        return hashlib.sha3_256(combined).digest()


def demo_hybrid_exchange():
    """演示完整的混合密钥交换流程"""
    print("混合密钥交换演示 (ECDH + Code-Based KEM)")
    print("=" * 60)
    
    for pq_alg in ["BIKE-L1", "Classic-McEliece-348864", "HQC-128"]:
        try:
            print(f"\n--- 使用 {pq_alg} ---")
            
            # Alice 和 Bob 各自初始化
            alice = HybridKeyExchange(pq_alg)
            bob = HybridKeyExchange(pq_alg)
            
            # 交换公钥材料
            alice_material = alice.get_public_material()
            bob_material = bob.get_public_material()
            
            # Alice 生成共享密钥（发给 Bob）
            alice_shared = alice.encapsulate(
                bob_material["ecdh_public"],
                bob_material["pqc_public"]
            )
            
            # Bob 解封装 Alice 的密文
            bob_shared = bob.decapsulate(
                alice.ciphertext,
                alice_material["ecdh_public"]
            )
            
            # 验证
            if alice_shared == bob_shared:
                print(f"  ✅ 混合密钥交换成功!")
                print(f"     共享密钥: {alice_shared.hex()[:32]}...")
            else:
                print(f"  ❌ 密钥不匹配!")
                
        except oqs.MechanismNotEnabledError:
            print(f"  ⚠️  {pq_alg} 未启用，跳过")
        except Exception as e:
            print(f"  ❌ 错误: {e}")


if __name__ == "__main__":
    demo_hybrid_exchange()