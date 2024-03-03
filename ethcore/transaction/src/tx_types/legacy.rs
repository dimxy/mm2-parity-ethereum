// This source is derived from Parity code
//
//! Legacy transaction encoding/decoding and specific checks

use std::ops::Deref;
use ethereum_types::{H256, U256};
use hash::keccak;
use rlp::{self, RlpStream, Rlp, DecoderError};
use crate::SignedTransactionShared;

use super::{Action, TransactionShared};

type Bytes = Vec<u8>;

/// A set of information describing an externally-originating message call
/// or contract creation operation.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct LegacyTransaction {
	/// Nonce.
	pub nonce: U256,
	/// Gas price.
	pub gas_price: U256,
	/// Gas paid up front for transaction execution.
	pub gas: U256,
	/// Action, can be either call or contract create.
	pub action: Action,
	/// Transfered value.
	pub value: U256,
	/// Transaction data.
	pub data: Bytes,
}

impl LegacyTransaction {
	/// tx list item count
	fn payload_length(chain_id: Option<u64>) -> usize {
        if chain_id.is_none() { 6 } else { 9 }
    }

	/// Append object with a without signature into RLP stream
	fn rlp_append_unsigned_transaction(&self, s: &mut RlpStream, chain_id: Option<u64>) {
		s.begin_list(Self::payload_length(chain_id));
		s.append(&self.nonce);
		s.append(&self.gas_price);
		s.append(&self.gas);
		s.append(&self.action);
		s.append(&self.value);
		s.append(&self.data);
		if let Some(n) = chain_id {
			s.append(&n);
			s.append(&0u8);
			s.append(&0u8);
		}
	}
}

impl TransactionShared for LegacyTransaction {
	/// The message hash of the transaction.
	fn message_hash(&self, chain_id: Option<u64>) -> H256 {
		let mut stream = RlpStream::new();
		self.rlp_append_unsigned_transaction(&mut stream, chain_id);
		keccak(stream.as_raw())
	}
}

impl rlp::Decodable for LegacyTransaction {
	fn decode(d: &Rlp) -> Result<Self, DecoderError> {
		Ok(LegacyTransaction {
			nonce: d.val_at(0)?,
			gas_price: d.val_at(1)?,
			gas: d.val_at(2)?,
			action: d.val_at(3)?,
			value: d.val_at(4)?,
			data: d.val_at(5)?,
		})
	}
}


/// Signed transaction information without verified signature.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UnverifiedLegacyTransaction {
	/// Plain Transaction.
	pub unsigned: LegacyTransaction,
	/// The V field of the signature; the LS bit described which half of the curve our point falls
	/// in. The MS bits describe which chain this transaction is for. If 27/28, its for all chains.
	/// normally fixed with chain_id for Eip155
	pub network_v: u64,
	/// The R field of the signature; helps describe the point on the curve.
	pub r: U256,
	/// The S field of the signature; helps describe the point on the curve.
	pub s: U256,
	/// Hash of the transaction
	pub hash: H256,
}

impl Deref for UnverifiedLegacyTransaction {
	type Target = LegacyTransaction;

	fn deref(&self) -> &Self::Target {
		&self.unsigned
	}
}

impl rlp::Decodable for UnverifiedLegacyTransaction {
	fn decode(d: &Rlp) -> Result<Self, DecoderError> {
		if d.item_count()? != 9 {
			return Err(DecoderError::RlpIncorrectListLen);
		}
		let hash = keccak(d.as_raw());
		Ok(UnverifiedLegacyTransaction {
			unsigned: LegacyTransaction::decode(d)?,
			network_v: d.val_at(6)?,
			r: d.val_at(7)?,
			s: d.val_at(8)?,
			hash,
		})
	}
}

impl rlp::Encodable for UnverifiedLegacyTransaction {
	fn rlp_append(&self, s: &mut RlpStream) { self.rlp_append_sealed_transaction(s) }
}

impl SignedTransactionShared for UnverifiedLegacyTransaction {
	fn set_hash(&mut self, hash: H256) { self.hash = hash; }
}

impl UnverifiedLegacyTransaction {
	/// Append object with a signature into RLP stream
	pub(crate) fn rlp_append_sealed_transaction(&self, s: &mut RlpStream) {
		s.begin_list(9);
		s.append(&self.nonce);
		s.append(&self.gas_price);
		s.append(&self.gas);
		s.append(&self.action);
		s.append(&self.value);
		s.append(&self.data);
		s.append(&self.network_v);
		s.append(&self.r);
		s.append(&self.s);
	}

	pub fn standard_v(&self) -> u8 {
		eip155_methods::check_replay_protection(self.network_v)
	}

	pub fn to_network_v(v: u64, chain_id: Option<u64>) -> u64 {
		eip155_methods::add_chain_replay_protection(v, chain_id)
	}

	// EIP-86: Transactions of this form MUST have gasprice = 0, nonce = 0, value = 0, and do NOT increment the nonce of account 0.
	pub(crate) fn validate_eip86(&self) -> bool {
		self.gas_price.is_zero() && self.value.is_zero() && self.nonce.is_zero()
	}
}

/// Replay protection logic for v part of transaction's signature
pub mod eip155_methods {
	/// Adds chain id into v
	pub fn add_chain_replay_protection(v: u64, chain_id: Option<u64>) -> u64 {
		v + if let Some(n) = chain_id { 35 + n * 2 } else { 27 }
	}

	/// Returns refined v
	/// 0 if `v` would have been 27 under "Electrum" notation, 1 if 28 or 4 if invalid.
	pub fn check_replay_protection(v: u64) -> u8 {
		match v {
			v if v == 27 => 0,
			v if v == 28 => 1,
			v if v > 36 => ((v - 1) % 2) as u8,
			 _ => 4
		}
	}
}