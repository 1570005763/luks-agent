// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::str::FromStr;

use strum::{AsRefStr, EnumString};

use crate::{Decrypter, Error, Getter, ProviderSettings, Result};

const _IN_GUEST_DEFAULT_KEY_PATH: &str = "/etc";

#[cfg(feature = "aliyun")]
pub mod aliyun;

#[derive(AsRefStr, EnumString)]
pub enum DecryptorProvider {
    #[cfg(feature = "aliyun")]
    #[strum(ascii_case_insensitive)]
    Aliyun,
}

/// Create a new [`Decrypter`] by given provider name and [`ProviderSettings`]
pub async fn new_decryptor(
    provider_name: &str,
    _provider_settings: ProviderSettings,
) -> Result<Box<dyn Decrypter>> {
    let provider = DecryptorProvider::try_from(provider_name)
        .map_err(|_| Error::UnsupportedProvider(provider_name.to_string()))?;
    match provider {
        #[cfg(feature = "aliyun")]
        DecryptorProvider::Aliyun => Ok(Box::new(
            aliyun::AliyunKmsClient::from_provider_settings(&_provider_settings).await?,
        ) as Box<dyn Decrypter>),
    }
}

#[derive(AsRefStr, EnumString)]
pub enum VaultProvider {
    #[cfg(feature = "aliyun")]
    #[strum(ascii_case_insensitive)]
    Aliyun,
}

/// Create a new [`Getter`] by given provider name and [`ProviderSettings`]
pub async fn new_getter(
    provider_name: &str,
    _provider_settings: ProviderSettings,
) -> Result<Box<dyn Getter>> {
    let provider = VaultProvider::from_str(provider_name)
        .map_err(|_| Error::UnsupportedProvider(provider_name.to_string()))?;
    match provider {
        #[cfg(feature = "aliyun")]
        VaultProvider::Aliyun => Ok(Box::new(
            aliyun::AliyunKmsClient::from_provider_settings(&_provider_settings).await?,
        ) as Box<dyn Getter>),
    }
}
