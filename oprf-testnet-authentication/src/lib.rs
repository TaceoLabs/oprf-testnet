use alloy::primitives::U160;
use std::fmt;
use taceo_oprf::types::OprfKeyId;

pub mod basic;
mod unkey_api;
pub mod wallet_ownership;

#[derive(Debug, Clone)]
pub enum AuthModule {
    Basic,
    WalletOwnership,
}

impl AuthModule {
    pub fn to_path(&self) -> String {
        format!("/{self}")
    }

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
