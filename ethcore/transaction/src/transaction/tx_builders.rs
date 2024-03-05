//! Transaction builders

use super::{Bytes, eip1559::AccessList, Action, TransactionWrapper, U256, Eip1559Transaction, LegacyTransaction};

#[derive(Debug, PartialEq, Clone)]
pub enum TxBuilderError {
    /// No gas price or priority fee per gas set 
    NoGasPriceSet,
    /// Chain_id must be set for tx type >= 1 
    NoChainIdSet,
}

pub struct TransactionWrapperBuilder {
	chain_id: Option<u64>,
	nonce: U256,
    gas_price: Option<U256>,
	max_fee_per_gas: Option<U256>,
	max_priority_fee_per_gas: Option<U256>,
	gas: U256,
	action: Action,
	value: U256,
	data: Bytes,
	access_list: Option<AccessList>,
}

impl TransactionWrapperBuilder {
    pub fn new(nonce: U256, gas: U256, action: Action, value: U256, data: Bytes) -> Self {
        Self {
            chain_id: None,
            nonce,
            gas,
            gas_price: None,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            action, 
            value,
            data,
            access_list: None,
        }
    }

    pub fn with_chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = Some(chain_id);
        self
    }

    pub fn with_gas_price(mut self, gas_price: U256) -> Self {
        self.gas_price = Some(gas_price);
        self
    }

    pub fn with_priority_fee_per_gas(mut self, max_fee_per_gas: U256, max_priority_fee_per_gas: U256) -> Self {
        self.max_fee_per_gas = Some(max_fee_per_gas);
        self.max_priority_fee_per_gas = Some(max_priority_fee_per_gas);
        self
    }

    pub fn with_access_list(mut self, access_list: AccessList) -> Self {
        self.access_list = Some(access_list);
        self
    }

    pub fn build(self) -> Result<TransactionWrapper, TxBuilderError> {
        if let Some(gas_price) = self.gas_price {
            Ok(TransactionWrapper::Legacy(LegacyTransaction {
                nonce: self.nonce,
                gas_price,
                gas: self.gas,
                action: self.action,
                value: self.value,
                data: self.data,
            }))

        } else if let (Some(max_fee_per_gas), Some(max_priority_fee_per_gas), Some(chain_id)) = 
            (self.max_fee_per_gas, self.max_priority_fee_per_gas, self.chain_id) {
            Ok(TransactionWrapper::Eip1559(Eip1559Transaction {
                chain_id,
                nonce: self.nonce,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                gas: self.gas,
                action: self.action,
                value: self.value,
                data: self.data,
                access_list: if let Some(access_list) = self.access_list { access_list } else { AccessList::default() },
            }))
        } else {
            if !matches!(self.chain_id, Some(_chain_id)) {
                Err(TxBuilderError::NoChainIdSet)
            } else {
                Err(TxBuilderError::NoGasPriceSet)
            }
        }
    }
}