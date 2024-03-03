// This source is derived from Parity code
//
//! Eip 1559 transaction encoding/decoding and specific checks

use std::{convert::TryInto, ops::Deref};
use ethereum_types::{H256, U256};
use hash::keccak;
use rlp::{self, RlpStream, Rlp, DecoderError};
use super::SignedTransactionShared;
use super::{Action, TransactionShared};
use super::eip2930::AccessList;

type Bytes = Vec<u8>;

pub const EIP1559_TX_TYPE: u8 = 2;

/// A set of information describing an externally-originating message call
/// or contract creation operation.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Eip1559Transaction {
    /// Simple replay attack protection
    pub chain_id: u64,
	/// Nonce.
	pub nonce: U256,
	/// Max fee per gas.
	pub max_fee_per_gas: U256,
	/// Max priority fee per gas.
	pub max_priority_fee_per_gas: U256,
	/// Gas paid up front for transaction execution.
	pub gas: U256,
	/// Action, can be either call or contract create.
	pub action: Action,
	/// Transfered value.
	pub value: U256,
	/// Transaction data.
	pub data: Bytes,
    /// Access list.
    pub access_list: AccessList,
}

impl Eip1559Transaction {
    const fn payload_length(&self) -> usize { 9 }

	/// Append object with a without signature into RLP stream
	fn rlp_append_unsigned_transaction(&self, s: &mut RlpStream) {
        s.append(&EIP1559_TX_TYPE);
		s.begin_list(self.payload_length());
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
	/// The message hash of the transaction.
	fn message_hash(&self, _chain_id: Option<u64>) -> H256 {
		let mut stream = RlpStream::new();
		self.rlp_append_unsigned_transaction(&mut stream);
		keccak(stream.as_raw())
	}
}

impl rlp::Decodable for Eip1559Transaction {
	fn decode(d: &Rlp) -> Result<Self, DecoderError> {
		if d.as_raw().len() < 2 { return Err(DecoderError::RlpIsTooShort); }
        let version: u8 = d.as_raw()[0];
        if version != EIP1559_TX_TYPE { return Err(DecoderError::Custom("bad tx version")); }
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
	pub unsigned: Eip1559Transaction,
	/// The V field of the signature
	pub v: u64,
	/// The R field of the signature; helps describe the point on the curve.
	pub r: U256,
	/// The S field of the signature; helps describe the point on the curve.
	pub s: U256,
	/// Hash of the transaction
	pub hash: H256,
}

impl Deref for UnverifiedEip1559Transaction {
	type Target = Eip1559Transaction;

	fn deref(&self) -> &Self::Target {
		&self.unsigned
	}
}

impl rlp::Decodable for UnverifiedEip1559Transaction {
	fn decode(d: &Rlp) -> Result<Self, DecoderError> {
		let unsigned = Eip1559Transaction::decode(d)?;
		let hash = keccak(d.as_raw());
		let offset = unsigned.payload_length();
		if d.as_raw().len() < 1 { return Err(DecoderError::RlpIsTooShort); }
		let list = Rlp::new(&d.as_raw()[1..]);
		Ok(UnverifiedEip1559Transaction {
			unsigned,
			v: list.val_at(offset)?,
			r: list.val_at(offset+1)?,
			s: list.val_at(offset+2)?,
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
	/// tx list item count
	fn payload_length(&self) -> usize {
		self.unsigned.payload_length() + 3
    }

	/// Append object with a signature into RLP stream
	pub(crate) fn rlp_append_sealed_transaction(&self, s: &mut RlpStream) {
		s.append(&EIP1559_TX_TYPE);
		s.begin_list(self.payload_length());
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
		self.v.try_into().unwrap_or_default() // we should have parity 0 or 1  for v2 txns
	}

	// EIP-86 or newer: Transactions of this form MUST have gasprice = 0, nonce = 0, value = 0, and do NOT increment the nonce of account 0.
	pub(crate) fn _validate_empty_sig(&self) -> bool {
		true // TODO fix for eip1559
	}
}
