"""
Domain-specific request/response handlers and interceptors.
"""

import re
import hashlib
from typing import Optional, Dict, Tuple

class DomainHandlerRegistry:
    """Điều phối các bộ xử lý đặc biệt cho từng domain cụ thể."""

    @staticmethod
    def extract_laodong_cookie(html: str) -> Optional[str]:
        """Trích xuất cookie xác thực D1N từ trang thử thách JavaScript của Lao Động."""
        match = re.search(r'document\.cookie\s*=\s*["\'](D1N=[^;"\']+)["\']', html)
        if match:
            return match.group(1)
        return None

    @staticmethod
    def solve_ncbi_pow(html: str) -> Optional[Tuple[str, int]]:
        """
        Giải thử thách Proof-of-Work (PoW) SHA-256 của NCBI/PubMed (HTTP 203).
        Tìm nonce sao cho SHA256(challengeId:nonce) có ít nhất 'bits' số 0 ở đầu.
        Trả về (challenge_id, nonce) hoặc None nếu không phải trang PoW.
        """
        c_match = re.search(r'const challengeId = "([^"]+)";', html)
        b_match = re.search(r'const bits = (\d+);', html)
        if not c_match or not b_match:
            return None

        challenge_id = c_match.group(1)
        try:
            bits = int(b_match.group(1))
        except ValueError:
            bits = 12

        def leading_zeros(bytes_data: bytes) -> int:
            total = 0
            for byte in bytes_data:
                if byte == 0:
                    total += 8
                else:
                    for bit in range(7, -1, -1):
                        if (byte & (1 << bit)) == 0:
                            total += 1
                        else:
                            return total
                    return total
            return total

        nonce = 0
        while True:
            text = f"{challenge_id}:{nonce}".encode("utf-8")
            digest = hashlib.sha256(text).digest()
            if leading_zeros(digest) >= bits:
                return challenge_id, nonce
            nonce += 1

    @staticmethod
    def get_custom_headers(domain: str) -> Dict[str, str]:
        """Tùy chỉnh headers riêng cho từng domain nếu cần."""
        headers = {}
        if domain == "vnexpress.net":
            headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
            headers["Accept-Language"] = "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7"
        elif "pubmed.ncbi.nlm.nih.gov" in domain or "ncbi.nlm.nih.gov" in domain:
            headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
            headers["Accept-Language"] = "en-US,en;q=0.9"
            headers["Upgrade-Insecure-Requests"] = "1"
        return headers
