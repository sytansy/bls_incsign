This is the codes for the BLS multi-signature (BLS-MS) scheme introduced in the paper [Efficient Fork-Free BLS Multi-signature Scheme with Incremental Signing](https://link.springer.com/chapter/10.1007/978-981-96-0954-3_13):
- uf-cma secure without relying on the forking lemma
- supports incremental signing
- more efficient PK aggregation algorithm, and therefore a faster MS verification algorithm, than that in the BDN-MS

It adopts the BLS codes from [MIRACL Core Cryptographic Library](https://github.com/miracl/core) (Dec 2023).
