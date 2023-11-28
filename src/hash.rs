const FNV_INIT: u32 = 0x811c9dc5;
const FNV_PRIME: u32 = 0x01000193;

/// Generate FNV1a hash of a given string and automatically converting upper to
/// lower-case
///
/// # Arguments
///
/// * `value`: ASCII string
///
/// returns: u32
#[inline(always)]
pub const fn fnv1a_ci(value: &[u8]) -> u32 {
    let mut hash = FNV_INIT;
    let mut i = 0;
    while i < value.len() {
        let value = value[i].to_ascii_lowercase();
        hash = hash.wrapping_mul(FNV_PRIME);
        hash ^= value as u32;
        i += 1;
    }
    hash
}

/// Generate FNV1a hash of a given string and automatically converting upper to
/// lower-case, and handling each character as 1 byte.
///
/// # Arguments
///
/// * `value`: Wide ASCII string
///
/// returns: u32
#[inline(always)]
pub const fn fnv1a_wci(value: &[u16]) -> u32 {
    let mut hash = FNV_INIT;
    let mut i = 0;
    while i < value.len() {
        let value = (value[i] as u8).to_ascii_lowercase();
        hash = hash.wrapping_mul(FNV_PRIME);
        hash ^= value as u32;
        i += 1;
    }
    hash
}
