#
#  PublicKey/PKCS8.py : PKCS#8 functions
#
# SPDX-FileCopyrightText: 2014 Legrandin <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause


from __future__ import annotations

from typing import Optional, Union

from Crypto.Util.asn1 import DerSequence

from ECC import DerObjectId, DerOctetString

__all__ = ["wrap", "unwrap", "UnwrappedKey"]


#: Encryption scheme of a private key, when the ``protection`` is not specified
DEFAULT_PROTECTION = "PBKDF2WithHMAC-SHA256AndAES256-CBC"


class UnwrappedKey(tuple[str, bytes, Optional[bytes]]):
    public_key: Optional[bytes]

    @classmethod
    def _create(
        cls,
        oid: str,
        private_key: bytes,
        params: Optional[bytes],
        public_key: Optional[bytes],
    ) -> UnwrappedKey:
        result = cls((oid, private_key, params))
        result.public_key = public_key
        return result

def unwrap(
    p8_private_key: bytes,
    passphrase: Optional[Union[bytes, str]] = None,
    max_iteration_count: Optional[int] = None,
    *,
    threads: int = 1,
    max_memory: Optional[int] = None,
) -> UnwrappedKey:
    pk_info = DerSequence().decode(p8_private_key, nr_elements=(2, 3, 4, 5))
    algo = DerSequence().decode(pk_info[1], nr_elements=(1, 2))
    algo_oid = DerObjectId().decode(algo[0]).value
    algo_params = None if len(algo) == 1 else algo[1]
    private_key = DerOctetString().decode(pk_info[2]).payload
    public_key = None


    return UnwrappedKey._create(algo_oid, private_key, algo_params, public_key)