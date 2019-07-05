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

// #![warn(missing_docs)]

extern crate byteorder;
extern crate edit_distance;
extern crate ethereum_types;
extern crate mem;
extern crate rand;
extern crate rustc_hex;
extern crate secp256k1;
extern crate serde;
extern crate tiny_keccak;

#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;

mod error;
mod keypair;
mod keccak;
mod password;
mod prefix;
mod random;
mod signature;
mod secret;

pub use self::error::Error;
pub use self::keypair::{KeyPair, public_to_address};
pub use self::password::Password;
pub use self::prefix::Prefix;
pub use self::random::Random;
pub use self::signature::{recover, sign, Signature};
pub use self::secret::Secret;

use ethereum_types::H256;

pub use ethereum_types::{Address, Public};
pub type Message = H256;

/// Uninstantiatable error type for infallible generators.
#[derive(Debug)]
pub enum Void {}

/// Generates new keypair.
pub trait Generator {
	type Error;

	/// Should be called to generate new keypair.
	fn generate(&mut self) -> Result<KeyPair, Self::Error>;
}
