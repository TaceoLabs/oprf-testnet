//! Example authentication modules used in the TACEO:OPRF testnet.
#![deny(missing_docs)]
use alloy::primitives::U160;
use std::fmt;
use taceo_oprf::types::OprfKeyId;

pub mod basic;
mod unkey_api;
pub mod wallet_ownership;

/// The two authentication modules used in the TACEO:OPRF testnet. Each module has a unique path and OPRF key ID.
#[derive(Debug, Clone)]
pub enum AuthModule {
    /// A simple authentication module that just verifies an API key for validity.
    Basic,
    /// A more complex authentication module that verifies ownership of a wallet by signing a message with the wallet's private key.
    WalletOwnership,
}

impl AuthModule {
    /// Returns the path for this authentication module, which is used in the API endpoint.
    pub fn to_path(&self) -> String {
        format!("/{self}")
    }

    /// Returns the OPRF key ID for this authentication module, which is used to identify the OPRF key that should be used for this module.
    ///
    /// For this example it is just hardcoded and limited to a single key per module, but in a real implementation this could be more dynamic and support multiple keys per module.
    pub fn oprf_key_id(&self) -> OprfKeyId {
        match self {
            Self::Basic => OprfKeyId::new(U160::from(1)),
            Self::WalletOwnership => OprfKeyId::new(U160::from(2)),
        }
    }
}

impl fmt::Display for AuthModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Basic => "basic",
            Self::WalletOwnership => "wallet-ownership",
        };
        write!(f, "{s}")
    }
}
