## transaction-core

In order for any payments network to function, it must be able to maintain a history of transactions. MobileCoin Ledger describes how the MobileCoin Network stores payment records in a public ledger. The ledger is implemented as a blockchain, in which each block contains transactions that include transaction outputs (*txos*) that might be spent in the future by their owners. Each transaction also includes a proof that all value spent in the transaction has never been spent before. The underlying design is based on the privacy-preserving CryptoNote ledger protocol, which obscures the identity of all *txo* owners using one-time recipient addresses. The link between sender and recipient is protected through the use of input rings that guard the actually-spent *txo* in a large set of possibly-spent *txos*.

The monetary value of each *txo* is encrypted using the method of Ring Confidential Transactions (RingCT). RingCT is implemented using bulletproofs for improved performance. Only the receiver of the transaction can reveal the encrypted monetary value and spend the new *txos* that are written to the ledger. The recipient’s cryptographic control over spending ensures that all transactions in MobileCoin are irreversible, similar to cash transactions in the real world.

Each *txo* in the input ring of a transaction is annotated with a Merkle proof of inclusion in the MobileCoin Ledger blockchain. This allows new transactions to be validated with fewer blockchain read operations, improving efficiency and reducing information leaked to data-access side channels.

Additionally, MobileCoin Ledger dramatically improves on the baseline privacy offered by CryptoNote and RingCT by requiring that the input rings for every transaction are deleted before the new payment is added to the public ledger. Digital signatures are added to the ledger in place of the full transaction records to provide a basis for auditing.

This crate provides a `no_std` implementation of the MobileCoin transaction.

### References

* [CryptoNote Whitepaper](https://cryptonote.org/whitepaper.pdf)
* [CryptoNote One Time Addresses](https://cryptonote.org/cns/cns007.txt)
* [Ring Signatures: How to Leak a Secret](https://www.iacr.org/archive/asiacrypt2001/22480554.pdf)
* [Ring Confidential Transactions](https://eprint.iacr.org/2015/1098.pdf)
* [Bulletproofs](https://eprint.iacr.org/2017/1066.pdf)
