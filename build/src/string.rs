use rand::Rng;

pub fn obfuscate_string(value: &str) -> Vec<u8> {
    let mut value = value.as_bytes().to_vec();
    let key = value[rand::thread_rng().gen_range(0..value.len())];
    value.push(0);
    for c in value.iter_mut() {
        *c = *c ^ key
    }
    value
}
