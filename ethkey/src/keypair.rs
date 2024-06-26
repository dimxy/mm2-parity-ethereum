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
use secp256k1::{PublicKey, SecretKey, Secp256k1};
use rustc_hex::ToHex;
use keccak::Keccak256;
use super::{Secret, Public, Address, Error};

pub fn public_to_address(public: &Public) -> Address {
	let hash = public.as_bytes().keccak256();
	let mut result = Address::default();
	result.as_mut().copy_from_slice(&hash[12..]);
	result
}

#[derive(Debug, Clone, PartialEq)]
/// secp256k1 key pair
pub struct KeyPair {
	secret: Secret,
	public: Public,
}

impl fmt::Display for KeyPair {
	fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		writeln!(f, "secret:  {}", self.secret.to_hex::<String>())?;
        writeln!(f, "public:  {}", self.public.as_bytes().to_hex::<String>())?;
        write!(f, "address: {}", self.address().as_bytes().to_hex::<String>())
	}
}

impl KeyPair {
	/// Create a pair from secret key
	pub fn from_secret(secret: Secret) -> Result<KeyPair, Error> {
		let s: SecretKey = SecretKey::from_slice(&secret[..])?;
		let pub_key = PublicKey::from_secret_key(&Secp256k1::new(), &s);
		let serialized = pub_key.serialize_uncompressed();

		let mut public = Public::default();
		public.as_mut().copy_from_slice(&serialized[1..65]);

		let keypair = KeyPair {
			secret,
			public,
		};

		Ok(keypair)
	}

	pub fn from_secret_slice(slice: &[u8]) -> Result<KeyPair, Error> {
		Self::from_secret(Secret::from_unsafe_slice(slice)?)
	}

	pub fn from_keypair(sec: SecretKey, publ: PublicKey) -> Self {
		let serialized = publ.serialize_uncompressed();
		let secret = Secret::from(sec);
		let mut public = Public::default();
		public.as_mut().copy_from_slice(&serialized[1..65]);

		KeyPair {
			secret,
			public,
		}
	}

	pub fn secret(&self) -> &Secret {
		&self.secret
	}

	pub fn public(&self) -> &Public {
		&self.public
	}

	pub fn address(&self) -> Address {
		public_to_address(&self.public)
	}
}

#[cfg(test)]
mod tests {
	use std::str::FromStr;
	use {KeyPair, Secret};

	#[test]
	fn from_secret() {
		let secret = Secret::from_str("a100df7a048e50ed308ea696dc600215098141cb391e9527329df289f9383f65").unwrap();
		let _ = KeyPair::from_secret(secret).unwrap();
	}

	#[test]
	fn keypair_display() {
		let expected =
"secret:  a100df7a048e50ed308ea696dc600215098141cb391e9527329df289f9383f65
public:  8ce0db0b0359ffc5866ba61903cc2518c3675ef2cf380a7e54bde7ea20e6fa1ab45b7617346cd11b7610001ee6ae5b0155c41cad9527cbcdff44ec67848943a4
address: 5b073e9233944b5e729e46d618f0d8edf3d9c34a".to_owned();
		let secret = Secret::from_str("a100df7a048e50ed308ea696dc600215098141cb391e9527329df289f9383f65").unwrap();
		let kp = KeyPair::from_secret(secret).unwrap();
		assert_eq!(format!("{}", kp), expected);
	}
}
