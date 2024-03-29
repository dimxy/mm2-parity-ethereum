//! Transaction builders
use super::{AccessList, Action, Bytes, Eip1559Transaction, Eip2930Transaction, LegacyTransaction, TransactionWrapper,
            TxType, U256};
use std::fmt;

#[derive(Debug, PartialEq, Clone)]
pub enum TxBuilderError {
    /// Invalid tx type
    InvalidTxType,
    /// No gas price
    NoGasPriceSet,
    /// No max gas fee or priority fee set
    NoFeePerGasSet,
    /// Chain id must be set for tx type >= 1
    NoChainIdSet,
}

impl fmt::Display for TxBuilderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg: String = match *self {
            TxBuilderError::InvalidTxType => "Invalid transaction type set".into(),
            TxBuilderError::NoGasPriceSet => "No gas price set".into(),
            TxBuilderError::NoFeePerGasSet => "No gas fee or priority fee per gas set".into(),
            TxBuilderError::NoChainIdSet => "Chain id must be set".into(),
        };
        f.write_fmt(format_args!("Transaction builder error ({})", msg))
    }
}

pub struct TransactionWrapperBuilder {
    tx_type: TxType,
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
    pub fn new(tx_type: TxType, nonce: U256, gas: U256, action: Action, value: U256, data: Bytes) -> Self {
        Self {
            tx_type,
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
        match self.tx_type {
            TxType::Legacy => Ok(TransactionWrapper::Legacy(LegacyTransaction {
                nonce: self.nonce,
                gas_price: self.gas_price.ok_or(TxBuilderError::NoGasPriceSet)?,
                gas: self.gas,
                action: self.action,
                value: self.value,
                data: self.data,
            })),
            TxType::Type1 => Ok(TransactionWrapper::Eip2930(Eip2930Transaction {
                chain_id: self.chain_id.ok_or(TxBuilderError::NoChainIdSet)?,
                nonce: self.nonce,
                gas_price: self.gas_price.ok_or(TxBuilderError::NoGasPriceSet)?,
                gas: self.gas,
                action: self.action,
                value: self.value,
                data: self.data,
                access_list: if let Some(access_list) = self.access_list {
                    access_list
                } else {
                    AccessList::default()
                },
            })),
            TxType::Type2 => Ok(TransactionWrapper::Eip1559(Eip1559Transaction {
                chain_id: self.chain_id.ok_or(TxBuilderError::NoChainIdSet)?,
                nonce: self.nonce,
                max_fee_per_gas: self.max_fee_per_gas.ok_or(TxBuilderError::NoFeePerGasSet)?,
                max_priority_fee_per_gas: self
                    .max_priority_fee_per_gas
                    .ok_or(TxBuilderError::NoFeePerGasSet)?,
                gas: self.gas,
                action: self.action,
                value: self.value,
                data: self.data,
                access_list: if let Some(access_list) = self.access_list {
                    access_list
                } else {
                    AccessList::default()
                },
            })),
            TxType::Invalid => Err(TxBuilderError::InvalidTxType),
        }
    }
}
