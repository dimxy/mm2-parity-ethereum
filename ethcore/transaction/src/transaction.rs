// This source is derived from Parity code
//
// Copyright 2015-2018 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

//! Transaction data structure.

use error;
use ethereum_types::{Address, H160, H256, U256};
use ethkey::{self, public_to_address, recover, Public, Secret, Signature};
use hash::keccak;
use rlp::{self, DecoderError, Rlp, RlpStream};
use std::convert::TryInto;
use std::ops::Deref;

pub mod tx_builders;
pub use self::tx_builders::TransactionWrapperBuilder;

mod legacy;
pub use self::legacy::{LegacyTransaction, UnverifiedLegacyTransaction};

mod eip1559;
pub use self::eip1559::{Eip1559Transaction, UnverifiedEip1559Transaction, EIP1559_TX_TYPE};

type BlockNumber = u64;
type Bytes = Vec<u8>;

/// Fake address for unsigned transactions as defined by EIP-86.
pub const UNSIGNED_SENDER: Address = H160([0xff; 20]);

/// System sender address for internal state updates.
pub const SYSTEM_ADDRESS: Address = H160([
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xfe,
]);

/// Transaction action type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
	/// Create creates new contract.
	Create,
	/// Calls contract at given address.
	/// In the case of a transfer, this is the receiver's address.'
	Call(Address),
}

impl Default for Action {
	fn default() -> Action {
		Action::Create
	}
}

impl rlp::Decodable for Action {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		if rlp.is_empty() {
			Ok(Action::Create)
		} else {
			Ok(Action::Call(rlp.as_val()?))
		}
	}
}

impl rlp::Encodable for Action {
	fn rlp_append(&self, s: &mut RlpStream) {
		match *self {
			Action::Create => s.append_internal(&""),
			Action::Call(ref addr) => s.append_internal(addr),
		};
	}
}

/// Transaction activation condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
	/// Valid at this block number or later.
	Number(BlockNumber),
	/// Valid at this unix time or later.
	Timestamp(u64),
}

type TransactionSharedRet = dyn TransactionShared + Send + Sync + 'static;

/// Methods common for all tx versions
pub trait TransactionShared {
	fn nonce(&self) -> U256;

	fn action(&self) -> &Action;

	fn value(&self) -> U256;

	fn data(&self) -> &Bytes;

	fn message_hash(&self, chain_id: Option<u64>) -> H256;
}

/// Methods common all signed tx versions
pub trait SignedTransactionShared {
	fn compute_hash(mut self) -> Self
	where
		Self: rlp::Encodable + Sized,
	{
		let hash = keccak(&*self.rlp_bytes());
		self.set_hash(hash);
		self
	}

	fn set_hash(&mut self, hash: H256);
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TransactionWrapper {
	Legacy(LegacyTransaction),
	Eip1559(Eip1559Transaction),
}

impl TransactionWrapper {
	/// The message hash of the transaction.
	pub fn message_hash(&self, chain_id: Option<u64>) -> H256 {
		match self {
			TransactionWrapper::Legacy(tx) => tx.message_hash(chain_id),
			TransactionWrapper::Eip1559(tx) => tx.message_hash(None),
		}
	}

	/// Signs the transaction as coming from `sender`.
	pub fn sign(self, secret: &Secret, chain_id: Option<u64>) -> SignedTransaction {
		let sig = ::ethkey::sign(secret, &self.message_hash(chain_id))
			.expect("data is valid and context has signing capabilities; qed");
		SignedTransaction::new(self.with_signature(sig, chain_id))
			.expect("secret is valid so it's recoverable")
	}

	/// Add signature to the transaction.
	fn with_signature(self, sig: Signature, chain_id: Option<u64>) -> UnverifiedTransactionWrapper {
		UnverifiedTransactionWrapper::new(
			self,
			sig.r().into(),
			sig.s().into(),
			sig.v() as u64,
			chain_id,
			H256::from_low_u64_ne(0),
		)
		.compute_hash()
	}

	/// Useful for test incorrectly signed transactions.
	#[cfg(test)]
	pub fn invalid_sign(self) -> UnverifiedTransactionWrapper {
		UnverifiedTransactionWrapper::new(
			self,
			U256::one(),
			U256::one(),
			0,
			None,
			H256::from_low_u64_ne(0),
		)
		.compute_hash()
	}

	/// Specify the sender; this won't survive the serialize/deserialize process, but can be cloned.
	pub fn fake_sign(self, from: Address) -> SignedTransaction {
		SignedTransaction {
			transaction: UnverifiedTransactionWrapper::new(
				self,
				U256::one(),
				U256::one(),
				0,
				None,
				H256::from_low_u64_ne(0),
			)
			.compute_hash(),
			sender: from,
			public: None,
		}
	}

	/// Add EIP-86 compatible empty signature.
	pub fn null_sign(self, chain_id: u64) -> SignedTransaction {
		SignedTransaction {
			transaction: UnverifiedTransactionWrapper::new(
				self,
				U256::zero(),
				U256::zero(),
				chain_id,
				None,
				H256::from_low_u64_ne(0),
			)
			.compute_hash(),
			sender: UNSIGNED_SENDER,
			public: None,
		}
	}
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum UnverifiedTransactionWrapper {
	Legacy(UnverifiedLegacyTransaction),
	Eip1559(UnverifiedEip1559Transaction),
}

impl rlp::Decodable for UnverifiedTransactionWrapper {
	fn decode(d: &Rlp) -> Result<Self, DecoderError> {
		if is_typed_transaction(d) {
			// first byte is tx version
			match d.as_raw()[0] {
				EIP1559_TX_TYPE => Ok(UnverifiedTransactionWrapper::Eip1559(
					UnverifiedEip1559Transaction::decode(d)?,
				)),
				_ => Err(DecoderError::Custom("unsupported tx version")),
			}
		} else {
			Ok(UnverifiedTransactionWrapper::Legacy(UnverifiedLegacyTransaction::decode(d)?))
		}
	}
}

impl UnverifiedTransactionWrapper {
	fn new(
		tx: TransactionWrapper,
		r: U256,
		s: U256,
		v: u64,
		chain_id: Option<u64>,
		hash: H256,
	) -> Self {
		match tx {
			TransactionWrapper::Legacy(unsigned) => {
				UnverifiedTransactionWrapper::Legacy(UnverifiedLegacyTransaction {
					unsigned,
					r,
					s,
					network_v: UnverifiedLegacyTransaction::to_network_v(v, chain_id),
					hash,
				})
			}
			TransactionWrapper::Eip1559(unsigned) => {
				UnverifiedTransactionWrapper::Eip1559(UnverifiedEip1559Transaction {
					unsigned,
					r,
					s,
					v: v.try_into().unwrap(),
					hash,
				})
			}
		}
	}

	fn compute_hash(self) -> UnverifiedTransactionWrapper {
		match self {
			UnverifiedTransactionWrapper::Legacy(tx) => {
				UnverifiedTransactionWrapper::Legacy(tx.compute_hash())
			}
			UnverifiedTransactionWrapper::Eip1559(tx) => {
				UnverifiedTransactionWrapper::Eip1559(tx.compute_hash())
			}
		}
	}

	/// Append object with a signature into RLP stream
	fn rlp_append_sealed_transaction(&self, s: &mut RlpStream) {
		match self {
			UnverifiedTransactionWrapper::Legacy(tx) => tx.rlp_append_sealed_transaction(s),
			UnverifiedTransactionWrapper::Eip1559(tx) => tx.rlp_append_sealed_transaction(s),
		};
	}

	pub fn unsigned(&self) -> &TransactionSharedRet {
		match self {
			UnverifiedTransactionWrapper::Legacy(tx) => &tx.unsigned as &TransactionSharedRet,
			UnverifiedTransactionWrapper::Eip1559(tx) => &tx.unsigned as &TransactionSharedRet,
		}
	}

	/// Add eip155 fix to signature v, for legacy tx
	pub fn standard_v(&self) -> u8 {
		match self {
			UnverifiedTransactionWrapper::Legacy(tx) => tx.standard_v(),
			UnverifiedTransactionWrapper::Eip1559(tx) => tx.standard_v(),
		}
	}

	/// The chain ID, or `None` if this is a global transaction.
	pub fn chain_id_from_v(&self) -> Option<u64> {
		match self.v() {
			v if self.is_unsigned() => Some(v), // v is chain_id for null signer by eip-86 (TODO: is this supported?)
			v if v > 36 => Some((v - 35) / 2),  // encoded by eip-155
			_ => None,
		}
	}

	/// Construct a signature object from the sig.
	pub fn signature(&self) -> Signature {
		let r = h256_from_u256(self.r());
		let s = h256_from_u256(self.s());
		Signature::from_rsv(&r, &s, self.standard_v())
	}

	/// Checks whether the signature has a low 's' value.
	pub fn check_low_s(&self) -> Result<(), ethkey::Error> {
		if !self.signature().is_low_s() {
			Err(ethkey::Error::InvalidSignature.into())
		} else {
			Ok(())
		}
	}

	/// Checks is signature is empty.
	pub(crate) fn is_unsigned(&self) -> bool {
		self.r().is_zero() && self.s().is_zero()
	}

	/// Recovers the public key of the sender.
	pub fn recover_public(&self) -> Result<Public, ethkey::Error> {
		Ok(recover(&self.signature(), &self.unsigned().message_hash(self.chain_id_from_v()))?)
	}

	/// Do basic validation, checking for valid signature and minimum gas,
	// TODO: consider use in block validation.
	#[cfg(feature = "json-tests")]
	pub fn validate(
		self,
		schedule: &Schedule,
		require_low: bool,
		allow_chain_id_of_one: bool,
		allow_empty_signature: bool,
	) -> Result<UnverifiedTransaction, error::Error> {
		let chain_id = if allow_chain_id_of_one { Some(1) } else { None };
		self.verify_basic(require_low, chain_id, allow_empty_signature)?;
		if !allow_empty_signature || !self.is_unsigned() {
			self.recover_public()?;
		}
		if self.gas < U256::from(self.gas_required(&schedule)) {
			return Err(error::Error::InvalidGasLimit(::unexpected::OutOfBounds {
				min: Some(U256::from(self.gas_required(&schedule))),
				max: None,
				found: self.gas,
			})
			.into());
		}
		Ok(self)
	}

	/// Verify basic signature params. Does not attempt sender recovery.
	pub fn verify_basic(
		&self,
		check_low_s: bool,
		chain_id: Option<u64>,
		allow_empty_signature: bool,
	) -> Result<(), error::Error> {
		if check_low_s && !(allow_empty_signature && self.is_unsigned()) {
			self.check_low_s()?;
		}
		// Disallow unsigned transactions in case EIP-86 is disabled.
		if !allow_empty_signature && self.is_unsigned() {
			return Err(ethkey::Error::InvalidSignature.into());
		}

		if allow_empty_signature && self.is_unsigned() && self.validate_empty_sig() {
			return Err(ethkey::Error::InvalidSignature.into());
		}
		match (self.chain_id_from_v(), chain_id) {
			(None, _) => {}
			(Some(n), Some(m)) if n == m => {}
			_ => return Err(error::Error::InvalidChainId),
		};
		Ok(())
	}

	/// validate tx with empty signature
	fn validate_empty_sig(&self) -> bool {
		// Note: EIP-86 code was removed 
		false
	} 

	fn r(&self) -> U256 {
		match self {
			UnverifiedTransactionWrapper::Legacy(tx) => tx.r,
			UnverifiedTransactionWrapper::Eip1559(tx) => tx.r,
		}
	}
	fn s(&self) -> U256 {
		match self {
			UnverifiedTransactionWrapper::Legacy(tx) => tx.s,
			UnverifiedTransactionWrapper::Eip1559(tx) => tx.s,
		}
	}
	fn v(&self) -> u64 {
		match self {
			UnverifiedTransactionWrapper::Legacy(tx) => tx.network_v,
			UnverifiedTransactionWrapper::Eip1559(tx) => tx.v as u64,
		}
	}

	/// Get the hash of this transaction (keccak of the RLP).
	pub fn tx_hash(&self) -> H256 {
		match self {
			UnverifiedTransactionWrapper::Legacy(tx) => tx.hash,
			UnverifiedTransactionWrapper::Eip1559(tx) => tx.hash,
		}
	}
}

/// A `UnverifiedTransaction` with successfully recovered `sender`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SignedTransaction {
	pub transaction: UnverifiedTransactionWrapper,
	pub sender: Address,
	pub public: Option<Public>,
}

impl rlp::Encodable for SignedTransaction {
	fn rlp_append(&self, s: &mut RlpStream) {
		self.transaction.rlp_append_sealed_transaction(s)
	}
}

impl Deref for SignedTransaction {
	type Target = UnverifiedTransactionWrapper;
	fn deref(&self) -> &Self::Target {
		&self.transaction
	}
}

impl From<SignedTransaction> for UnverifiedTransactionWrapper {
	fn from(tx: SignedTransaction) -> Self {
		tx.transaction
	}
}

impl SignedTransaction {
	/// Try to verify transaction and recover sender.
	pub fn new(transaction: UnverifiedTransactionWrapper) -> Result<Self, ethkey::Error> {
		if transaction.is_unsigned() {
			Ok(SignedTransaction {
				transaction: transaction,
				sender: UNSIGNED_SENDER,
				public: None,
			})
		} else {
			let public = transaction.recover_public()?;
			let sender = public_to_address(&public);
			Ok(SignedTransaction {
				transaction: transaction,
				sender: sender,
				public: Some(public),
			})
		}
	}

	pub fn unsigned(&self) -> &TransactionSharedRet {
		match &self.transaction {
			UnverifiedTransactionWrapper::Legacy(tx) => &tx.unsigned as &TransactionSharedRet,
			UnverifiedTransactionWrapper::Eip1559(tx) => &tx.unsigned as &TransactionSharedRet,
		}
	}

	/// Returns transaction sender.
	pub fn sender(&self) -> Address {
		self.sender
	}

	/// Returns a public key of the sender.
	pub fn public_key(&self) -> Option<Public> {
		self.public
	}

	/// Checks is signature is empty.
	pub fn is_unsigned(&self) -> bool {
		self.transaction.is_unsigned()
	}

	/// Deconstructs this transaction back into `UnverifiedTransaction`
	pub fn deconstruct(self) -> (UnverifiedTransactionWrapper, Address, Option<Public>) {
		(self.transaction, self.sender, self.public)
	}
}

/// Signed Transaction that is a part of canon blockchain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalizedTransaction {
	/// Signed part.
	pub signed: UnverifiedTransactionWrapper,
	/// Block number.
	pub block_number: BlockNumber,
	/// Block hash.
	pub block_hash: H256,
	/// Transaction index within block.
	pub transaction_index: usize,
	/// Cached sender
	pub cached_sender: Option<Address>,
}

impl LocalizedTransaction {
	/// Returns transaction sender.
	/// Panics if `LocalizedTransaction` is constructed using invalid `UnverifiedTransaction`.
	pub fn sender(&mut self) -> Address {
		if let Some(sender) = self.cached_sender {
			return sender;
		}
		if self.is_unsigned() {
			return UNSIGNED_SENDER.clone();
		}
		let sender = public_to_address(&self.recover_public()
			.expect("LocalizedTransaction is always constructed from transaction from blockchain; Blockchain only stores verified transactions; qed"));
		self.cached_sender = Some(sender);
		sender
	}
}

impl Deref for LocalizedTransaction {
	type Target = UnverifiedTransactionWrapper;

	fn deref(&self) -> &Self::Target {
		&self.signed
	}
}

/// Queued transaction with additional information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingTransaction {
	/// Signed transaction data.
	pub transaction: SignedTransaction,
	/// To be activated at this condition. `None` for immediately.
	pub condition: Option<Condition>,
}

impl PendingTransaction {
	/// Create a new pending transaction from signed transaction.
	pub fn new(signed: SignedTransaction, condition: Option<Condition>) -> Self {
		PendingTransaction {
			transaction: signed,
			condition: condition,
		}
	}
}

impl Deref for PendingTransaction {
	type Target = SignedTransaction;

	fn deref(&self) -> &SignedTransaction {
		&self.transaction
	}
}

impl From<SignedTransaction> for PendingTransaction {
	fn from(t: SignedTransaction) -> Self {
		PendingTransaction { transaction: t, condition: None }
	}
}

/// Reproduces the same conversion as it was in the previous `ethereum-types-0.4` version:
/// https://docs.rs/ethereum-types/0.4.0/src/ethereum_types/hash.rs.html#32-38
fn h256_from_u256(num: U256) -> H256 {
	// `U256::to_big_endian` is used internally.
	let bytes: [u8; 32] = num.into();
	H256::from(bytes)
}

/// Returns true if serialized tx has type as in eip-2718
fn is_typed_transaction(d: &Rlp) -> bool {
	!d.is_list() && d.as_raw().len() > 0 && d.as_raw()[0] < 0x7f
}

#[cfg(test)]
mod tests {
	use super::*;
	use ethereum_types::U256;
	use ethkey::KeyPair;
	use hash::keccak;
	use std::str::FromStr;

	#[test]
	fn legacy_sender_test() {
		let bytes: Vec<u8> = ::rustc_hex::FromHex::from_hex("f85f800182520894095e7baea6a6c7c4c2dfeb977efac326af552d870a801ba048b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353a0efffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c804").unwrap();
		let t: UnverifiedTransactionWrapper =
			rlp::decode(&bytes).expect("decoding UnverifiedTransaction failed");
		if let UnverifiedTransactionWrapper::Legacy(legacy_tx) = t.clone() {
			assert_eq!(legacy_tx.data, b"");
			assert_eq!(legacy_tx.gas, U256::from(0x5208u64));
			assert_eq!(legacy_tx.gas_price, U256::from(0x01u64));
			assert_eq!(legacy_tx.nonce, U256::from(0x00u64));
			if let Action::Call(ref to) = legacy_tx.action {
				let expected =
					Address::from_str("095e7baea6a6c7c4c2dfeb977efac326af552d87").unwrap();
				assert_eq!(*to, expected);
			} else {
				panic!();
			}
			assert_eq!(legacy_tx.value, U256::from(0x0au64));
			let expected = Address::from_str("0f65fe9276bc9a24ae7083ae28e2660ef72df99e").unwrap();
			assert_eq!(public_to_address(&t.recover_public().unwrap()), expected);
			assert_eq!(t.chain_id_from_v(), None);
		} else {
			panic!("invalid tx ver");
		}
	}

	#[test]
	fn legacy_signing() {
		let key = KeyPair::from_secret_slice(&[
			128, 148, 101, 177, 125, 10, 77, 219, 62, 76, 105, 232, 242, 60, 44, 171, 173, 134,
			143, 81, 248, 190, 213, 199, 101, 173, 29, 101, 22, 195, 48, 111,
		])
		.unwrap();
		let t = TransactionWrapper::Legacy(LegacyTransaction {
			action: Action::Create,
			nonce: U256::from(42),
			gas_price: U256::from(3000),
			gas: U256::from(50_000),
			value: U256::from(1),
			data: b"Hello!".to_vec(),
		})
		.sign(&key.secret(), None);
		assert_eq!(Address::from(keccak(key.public())), t.sender());
		assert_eq!(t.chain_id_from_v(), None);
	}

	#[test]
	fn legacy_fake_signing() {
		let t = TransactionWrapper::Legacy(LegacyTransaction {
			action: Action::Create,
			nonce: U256::from(42),
			gas_price: U256::from(3000),
			gas: U256::from(50_000),
			value: U256::from(1),
			data: b"Hello!".to_vec(),
		})
		.fake_sign(Address::from_low_u64_ne(0x69));
		assert_eq!(Address::from_low_u64_ne(0x69), t.sender());
		assert_eq!(t.chain_id_from_v(), None);

		let t = t.clone();
		assert_eq!(Address::from_low_u64_ne(0x69), t.sender());
		assert_eq!(t.chain_id_from_v(), None);
	}

	#[test]
	fn legacy_should_recover_from_chain_specific_signing() {
		let key = KeyPair::from_secret_slice(&[
			128, 148, 101, 177, 125, 10, 77, 219, 62, 76, 105, 232, 242, 60, 44, 171, 173, 134,
			143, 81, 248, 190, 213, 199, 101, 173, 29, 101, 22, 195, 48, 111,
		])
		.unwrap();
		let t = TransactionWrapper::Legacy(LegacyTransaction {
			action: Action::Create,
			nonce: U256::from(42),
			gas_price: U256::from(3000),
			gas: U256::from(50_000),
			value: U256::from(1),
			data: b"Hello!".to_vec(),
		})
		.sign(&key.secret(), Some(69));
		assert_eq!(Address::from(keccak(key.public())), t.sender());
		assert_eq!(t.chain_id_from_v(), Some(69));
	}

	#[test]
	fn legacy_should_agree_with_vitalik() {
		use rustc_hex::FromHex;

		let test_vector = |tx_data: &str, address: &'static str| {
			let bytes: Vec<u8> = FromHex::from_hex(tx_data).unwrap();
			let signed = rlp::decode(&bytes).expect("decoding tx data failed");
			let signed = SignedTransaction::new(signed).unwrap();

			let expected = Address::from_str(address).unwrap();
			assert_eq!(signed.sender(), expected);
			println!("chainid_from_v: {:?}", signed.chain_id_from_v());
		};

		test_vector("f864808504a817c800825208943535353535353535353535353535353535353535808025a0044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116da0044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116d", "0xf0f6f18bca1b28cd68e4357452947e021241e9ce");
		test_vector("f864018504a817c80182a410943535353535353535353535353535353535353535018025a0489efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bcaa0489efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6", "0x23ef145a395ea3fa3deb533b8a9e1b4c6c25d112");
		test_vector("f864028504a817c80282f618943535353535353535353535353535353535353535088025a02d7c5bef027816a800da1736444fb58a807ef4c9603b7848673f7e3a68eb14a5a02d7c5bef027816a800da1736444fb58a807ef4c9603b7848673f7e3a68eb14a5", "0x2e485e0c23b4c3c542628a5f672eeab0ad4888be");
		test_vector("f865038504a817c803830148209435353535353535353535353535353535353535351b8025a02a80e1ef1d7842f27f2e6be0972bb708b9a135c38860dbe73c27c3486c34f4e0a02a80e1ef1d7842f27f2e6be0972bb708b9a135c38860dbe73c27c3486c34f4de", "0x82a88539669a3fd524d669e858935de5e5410cf0");
		test_vector("f865048504a817c80483019a28943535353535353535353535353535353535353535408025a013600b294191fc92924bb3ce4b969c1e7e2bab8f4c93c3fc6d0a51733df3c063a013600b294191fc92924bb3ce4b969c1e7e2bab8f4c93c3fc6d0a51733df3c060", "0xf9358f2538fd5ccfeb848b64a96b743fcc930554");
		test_vector("f865058504a817c8058301ec309435353535353535353535353535353535353535357d8025a04eebf77a833b30520287ddd9478ff51abbdffa30aa90a8d655dba0e8a79ce0c1a04eebf77a833b30520287ddd9478ff51abbdffa30aa90a8d655dba0e8a79ce0c1", "0xa8f7aba377317440bc5b26198a363ad22af1f3a4");
		test_vector("f866068504a817c80683023e3894353535353535353535353535353535353535353581d88025a06455bf8ea6e7463a1046a0b52804526e119b4bf5136279614e0b1e8e296a4e2fa06455bf8ea6e7463a1046a0b52804526e119b4bf5136279614e0b1e8e296a4e2d", "0xf1f571dc362a0e5b2696b8e775f8491d3e50de35");
		test_vector("f867078504a817c807830290409435353535353535353535353535353535353535358201578025a052f1a9b320cab38e5da8a8f97989383aab0a49165fc91c737310e4f7e9821021a052f1a9b320cab38e5da8a8f97989383aab0a49165fc91c737310e4f7e9821021", "0xd37922162ab7cea97c97a87551ed02c9a38b7332");
		test_vector("f867088504a817c8088302e2489435353535353535353535353535353535353535358202008025a064b1702d9298fee62dfeccc57d322a463ad55ca201256d01f62b45b2e1c21c12a064b1702d9298fee62dfeccc57d322a463ad55ca201256d01f62b45b2e1c21c10", "0x9bddad43f934d313c2b79ca28a432dd2b7281029");
		test_vector("f867098504a817c809830334509435353535353535353535353535353535353535358202d98025a052f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afba052f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afb", "0x3c24d7329e92f84f08556ceb6df1cdb0104ca49f");
	}

	#[test]
	fn eip1559_parse_tx() {
		use rustc_hex::FromHex;

		let test_vector = |tx_data: &str, address: &'static str, hash: &'static str| {
			let bytes: Vec<u8> = FromHex::from_hex(tx_data).unwrap();
			let unverified = rlp::decode(&bytes).expect("decoding tx data failed");
			let signed = SignedTransaction::new(unverified).unwrap();

			let expected_addr = Address::from_str(address).unwrap();
			assert_eq!(signed.sender(), expected_addr);
			let expected_hash = H256::from_str(hash).unwrap();
			let unverified_tx = signed.transaction.clone().compute_hash();
			assert_eq!(unverified_tx.tx_hash(), expected_hash);

			if let UnverifiedTransactionWrapper::Eip1559(tx) = signed.transaction {
				println!("chainid: {:?}", tx.chain_id);
			} else {
				panic!("expected tx type 2 (eip-1559)");
			}
		};

		// simple transfer eth tx
		test_vector("02f8710103830f42408518ad0849c4825208941749b8eccc622d81600ab7fa322a17b99def83d2876b803d5ccd438580c001a08303e62f4d7779b09ab9daeaef868a8ad3bc937b435a60e8cc432d224bd8b1fba0520ae4b5906f3978ff413eef4131c1d246b15eb676a19324ce9ad23ac48aa987", 
		"0xfAe06Df909Df46f3b1649c9b11e150F14E9B83B0", 
		"0x9903f6398f118dfc04b95ed6c00e55237eb204986590593d13e2f9ce47716ed9");
		// tx with data and access list
		test_vector("02f907670183180a51808507a6a2c507830917af946b75d8af000000e20b7a7ddf000ba900b4009a8080b89c0c8ee819c10e1f20df3a8c2ac93a62d7fba719fa777026c02d337617b02998480049642110b712c1fd7261bc074105e9e44676c68fc02aaa39b223fe8d0a0e5c4f27ead9083c756cc22710f2fe5250fe5318b03d536566b02998ffffc076c4ffff93001a6cd7c3a21bda7cf6a0cd5d5e8d10ab55d8ba58257813a239ca819d9510a73c424485f89ea52839fdb30640eb7dd7e0078e12fb0a4eac742df9065df89b94c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2f884a012231cd4c753cb5530a43a74c45106c24765e6f81dc8927d4f4be7e53315d5a8a093f4f2109c73365b91270de71d7ce61b41cfceb94f27f26e2b6e30142ea529e5a0af9987888ab75f8cdc0eee179dff704e6c0a13b462f58aac23ab8eb77f3d71cda0176d9f00066af884810a42c67ff9a8c1374be6135e1ee85edb8c9cf021f1fdd5f8dd94da7cf6a0cd5d5e8d10ab55d8ba58257813a239caf8c6a0000000000000000000000000000000000000000000000000000000000000000ca00000000000000000000000000000000000000000000000000000000000000008a00000000000000000000000000000000000000000000000000000000000000006a00000000000000000000000000000000000000000000000000000000000000007a00000000000000000000000000000000000000000000000000000000000000009a0000000000000000000000000000000000000000000000000000000000000000af8bc94993864e43caa7f7f12953ad6feb1d1ca635b875ff8a5a00000000000000000000000000000000000000000000000000000000000000003a0d93f987b59bbb5780fe5994c7112f10657809cae45c627a319f962c40235428ca0a6eabb9b2c010ec47045c52eb64682c8a09fe52a8605fef87ee312fa6817bde7a01f31c723d1f4395a6dac2d34827bb7577589384735f0df95b73389f4d27d8769a06e89d460fefb1c8f5b2b8f2e9609ee9a4ef3f9b7ff014be959a86fabed2b4af8f87a949ce9704b1993ff308f1815e0fd44b0dffee2d0dcf863a06d0cc4c200c8af0ffd8b254bae44f07d6bc5c15ac854d2a3dbf761299ffa9c56a0101ed5680b1cfc12bfd6f2c99ee49abcf5d75b12223f9040664d083b09f1c7d7a00000000000000000000000000000000000000000000000000000000000000002f8dd94424485f89ea52839fdb30640eb7dd7e0078e12fbf8c6a0000000000000000000000000000000000000000000000000000000000000000ca00000000000000000000000000000000000000000000000000000000000000008a00000000000000000000000000000000000000000000000000000000000000006a00000000000000000000000000000000000000000000000000000000000000007a00000000000000000000000000000000000000000000000000000000000000009a0000000000000000000000000000000000000000000000000000000000000000af9026a9419c10e1f20df3a8c2ac93a62d7fba719fa777026f90252a00000000000000000000000000000000000000000000000000000000000000004a00000000000000000000000000000000000000000000000000000000000000008a07350e62d400da1aad24eb98f7ba1200460b13fa4ebaebccf69f1ec15e9896737a02bb5540461adf3eb1d87affec4120ad02c1d3dfeb558a44a41bdb546360c8b2ca057e15af2cdc4ea5af6477be852d0d55b2e8b8039f955b0db7400692f43f35f78a02bb5540461adf3eb1d87affec4120ad02c1d3dfeb558a44a41bdb546360c8b2da057e15af2cdc4ea5af6477be852d0d55b2e8b8039f955b0db7400692f43f35f76a00000000000000000000000000000000000000000000000000000000000000002a0c0d1c00078410fd0164580b0bad93d8a579580d06cf45fc2696a823498097b8aa02bb5540461adf3eb1d87affec4120ad02c1d3dfeb558a44a41bdb546360c8b2aa02bb5540461adf3eb1d87affec4120ad02c1d3dfeb558a44a41bdb546360c8b2ba057e15af2cdc4ea5af6477be852d0d55b2e8b8039f955b0db7400692f43f35f75a00000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000001a07350e62d400da1aad24eb98f7ba1200460b13fa4ebaebccf69f1ec15e9896738a07350e62d400da1aad24eb98f7ba1200460b13fa4ebaebccf69f1ec15e9896739a07350e62d400da1aad24eb98f7ba1200460b13fa4ebaebccf69f1ec15e989673aa057e15af2cdc4ea5af6477be852d0d55b2e8b8039f955b0db7400692f43f35f77f8599449642110b712c1fd7261bc074105e9e44676c68ff842a0b39e9ba92c3c47c76d4f70e3bc9c3270ab78d2592718d377c8f5433a34d3470aa05f19933e8ecba477d24413f29da8dd3035e36ca249de114bc98ea28d251d02b580a0a00d83a12835ab9653ee11077d5dd310a424dd67885445f5319207e7a5a2ae15a059c4642a2ac77f31d88de1a4e0f70eb220be8a8219943c3af9cf9c71e3143ebd",
		"0xae2Fc483527B8EF99EB5D9B44875F005ba1FaE13",
		"0x256c91a7934b7584c1f8f28a6b3b8cacf13419637532896fc1e1119aa7fa32ba");
	}
}
