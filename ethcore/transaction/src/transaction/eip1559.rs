// This source is derived from Parity code
//
//! Eip 1559 transaction encoding/decoding and specific checks

use super::AccessList;
use super::SignedTransactionShared;
use super::{Action, Bytes, TransactionShared, TxType};
use crate::Error;
use ethereum_types::{H256, U256};
use hash::keccak;
use rlp::{self, DecoderError, Rlp, RlpStream};
use std::{convert::TryInto, ops::Deref};

/// A set of information describing an externally-originating message call
/// or contract creation operation.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Eip1559Transaction {
    /// Simple replay attack protection
    pub(crate) chain_id: u64,
    /// Nonce.
    pub(crate) nonce: U256,
    /// Max fee per gas.
    pub(crate) max_fee_per_gas: U256,
    /// Max priority fee per gas.
    pub(crate) max_priority_fee_per_gas: U256,
    /// Gas paid up front for transaction execution.
    pub(crate) gas: U256,
    /// Action, can be either call or contract create.
    pub(crate) action: Action,
    /// Transfered value.
    pub(crate) value: U256,
    /// Transaction data.
    pub(crate) data: Bytes,
    /// Access list.
    pub(crate) access_list: AccessList,
}

impl Eip1559Transaction {
    const fn payload_size(&self) -> usize { 9 }

    /// Append object with a without signature into RLP stream
    fn rlp_append_unsigned_transaction(&self, s: &mut RlpStream) {
        s.append(&(TxType::Type2 as u8));
        s.begin_list(self.payload_size());
        s.append(&self.chain_id);
        s.append(&self.nonce);
        s.append(&self.max_priority_fee_per_gas);
        s.append(&self.max_fee_per_gas);
        s.append(&self.gas);
        s.append(&self.action);
        s.append(&self.value);
        s.append(&self.data);
        s.append(&self.access_list);
    }
}

impl TransactionShared for Eip1559Transaction {
    fn nonce(&self) -> U256 { self.nonce }
    fn action(&self) -> &Action { &self.action }
    fn value(&self) -> U256 { self.value }
    fn data(&self) -> &Bytes { &self.data }
    /// The message hash of the transaction.
    fn message_hash(&self, _chain_id: Option<u64>) -> H256 {
        let mut stream = RlpStream::new();
        self.rlp_append_unsigned_transaction(&mut stream);
        keccak(stream.as_raw())
    }
}

impl rlp::Decodable for Eip1559Transaction {
    fn decode(d: &Rlp) -> Result<Self, DecoderError> {
        if d.as_raw().len() < 2 {
            return Err(DecoderError::RlpIsTooShort);
        }
        let version: u8 = d.as_raw()[0];
        if TxType::from(version) != TxType::Type2 {
            return Err(DecoderError::Custom("bad tx version"));
        }
        let list = Rlp::new(&d.as_raw()[1..]);
        Ok(Eip1559Transaction {
            chain_id: list.val_at(0)?,
            nonce: list.val_at(1)?,
            max_priority_fee_per_gas: list.val_at(2)?,
            max_fee_per_gas: list.val_at(3)?,
            gas: list.val_at(4)?,
            action: list.val_at(5)?,
            value: list.val_at(6)?,
            data: list.val_at(7)?,
            access_list: list.val_at(8)?,
        })
    }
}

/// Signed transaction information without verified signature.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UnverifiedEip1559Transaction {
    /// Plain Transaction.
    unsigned: Eip1559Transaction,
    /// The V field of the signature
    v: u64,
    /// The R field of the signature; helps describe the point on the curve.
    r: U256,
    /// The S field of the signature; helps describe the point on the curve.
    s: U256,
    /// Hash of the transaction
    hash: H256,
}

impl Deref for UnverifiedEip1559Transaction {
    type Target = Eip1559Transaction;

    fn deref(&self) -> &Self::Target { &self.unsigned }
}

impl rlp::Decodable for UnverifiedEip1559Transaction {
    fn decode(d: &Rlp) -> Result<Self, DecoderError> {
        let unsigned = Eip1559Transaction::decode(d)?;
        let hash = keccak(d.as_raw());
        let offset = unsigned.payload_size();
        let list = Rlp::new(&d.as_raw()[1..]);
        let v = list.val_at(offset)?;
        if !Self::validate_v(v) {
            return Err(DecoderError::Custom("invalid sig v"));
        }
        Ok(UnverifiedEip1559Transaction {
            unsigned,
            v,
            r: list.val_at(offset + 1)?,
            s: list.val_at(offset + 2)?,
            hash,
        })
    }
}

impl rlp::Encodable for UnverifiedEip1559Transaction {
    fn rlp_append(&self, s: &mut RlpStream) { self.rlp_append_sealed_transaction(s) }
}

impl SignedTransactionShared for UnverifiedEip1559Transaction {
    fn set_hash(&mut self, hash: H256) { self.hash = hash; }
}

impl UnverifiedEip1559Transaction {
    pub fn new(unsigned: Eip1559Transaction, r: U256, s: U256, v: u64, hash: H256) -> Result<Self, Error> {
        if !Self::validate_v(v) {
            return Err(Error::InvalidSignature("invalid sig v".into()));
        }
        Ok(UnverifiedEip1559Transaction {
            unsigned,
            r,
            s,
            v,
            hash,
        })
    }

    fn validate_v(v: u64) -> bool { (0..=1).contains(&v) }

    /// tx list item count
    fn payload_size(&self) -> usize { self.unsigned.payload_size() + 3 }

    /// Append object with a signature into RLP stream
    pub(crate) fn rlp_append_sealed_transaction(&self, s: &mut RlpStream) {
        s.append(&(TxType::Type2 as u8));
        s.begin_list(self.payload_size());
        s.append(&self.chain_id);
        s.append(&self.nonce);
        s.append(&self.max_priority_fee_per_gas);
        s.append(&self.max_fee_per_gas);
        s.append(&self.gas);
        s.append(&self.action);
        s.append(&self.value);
        s.append(&self.data);
        s.append(&self.access_list);
        s.append(&self.v);
        s.append(&self.r);
        s.append(&self.s);
    }

    pub fn standard_v(&self) -> u8 {
        self.v.try_into().expect("parity 0 or 1") // ensured that parity is 0 or 1 for tx type 2
    }

    pub fn r(&self) -> U256 { self.r }
    pub fn s(&self) -> U256 { self.s }
    pub fn v(&self) -> u64 { self.v }
    pub fn hash(&self) -> H256 { self.hash }
}
