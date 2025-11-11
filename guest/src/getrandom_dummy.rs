use core::num::NonZeroU32;
use getrandom::{register_custom_getrandom, Error};

fn custom_getrandom(_buf: &mut [u8]) -> Result<(), Error> {
    Err(Error::from(NonZeroU32::new(Error::UNSUPPORTED.code()).unwrap()))
}

register_custom_getrandom!(custom_getrandom);
