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

use std::fmt;
use std::ops::Deref;
use std::str::FromStr;
use rustc_hex::ToHex;
use secp256k1::{SecretKey};
use secp256k1::util::{SECRET_KEY_SIZE as SECP256K1_SECRET_KEY_SIZE};
use ethereum_types::H256;
use mem::Memzero;
use {Error};

#[derive(Clone, PartialEq, Eq)]
pub struct Secret {
	inner: Memzero<H256>,
}

impl ToHex for Secret {
	fn to_hex(&self) -> String {
		format!("{:x}", *self.inner)
	}
}

impl fmt::LowerHex for Secret {
	fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
		self.inner.fmt(fmt)
	}
}

impl fmt::Debug for Secret {
	fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
		self.inner.fmt(fmt)
	}
}

impl fmt::Display for Secret {
	fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
		write!(fmt, "Secret: 0x{:x}{:x}..{:x}{:x}", self.inner[0], self.inner[1], self.inner[30], self.inner[31])
	}
}

impl Secret {
	/// Creates a `Secret` from the given slice, returning `None` if the slice length != 32.
	pub fn from_slice(key: &[u8]) -> Option<Self> {
		if key.len() != 32 {
			return None
		}
		let mut h = H256::default();
		h.copy_from_slice(&key[0..32]);
		Some(Secret { inner: Memzero::from(h) })
	}

	/// Creates zero key, which is invalid for crypto operations, but valid for math operation.
	pub fn zero() -> Self {
		Secret { inner: Memzero::from(H256::default()) }
	}

	/// Imports and validates the key.
	pub fn from_unsafe_slice(key: &[u8]) -> Result<Self, Error> {
		let secret = SecretKey::parse_slice(key)?;
		Ok(secret.into())
	}

	/// Checks validity of this key.
	pub fn check_validity(&self) -> Result<(), Error> {
		self.to_secp256k1_secret().map(|_| ())
	}

	/// Create `secp256k1::key::SecretKey` based on this secret
	pub fn to_secp256k1_secret(&self) -> Result<SecretKey, Error> {
		Ok(SecretKey::parse_slice(&self[..])?)
	}
}

impl FromStr for Secret {
	type Err = Error;
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Ok(H256::from_str(s).map_err(|e| Error::Custom(format!("{:?}", e)))?.into())
	}
}

impl From<[u8; 32]> for Secret {
	fn from(k: [u8; 32]) -> Self {
		Secret { inner: Memzero::from(H256(k)) }
	}
}

impl From<H256> for Secret {
	fn from(s: H256) -> Self {
		s.0.into()
	}
}

impl From<&'static str> for Secret {
	fn from(s: &'static str) -> Self {
		s.parse().expect(&format!("invalid string literal for {}: '{}'", stringify!(Self), s))
	}
}

impl From<SecretKey> for Secret {
	fn from(key: SecretKey) -> Self {
		let mut a = [0; SECP256K1_SECRET_KEY_SIZE];
		a.copy_from_slice(&key.serialize()[0 .. SECP256K1_SECRET_KEY_SIZE]);
		a.into()
	}
}

impl Deref for Secret {
	type Target = H256;

	fn deref(&self) -> &Self::Target {
		&self.inner
	}
}
