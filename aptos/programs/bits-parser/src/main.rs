#![no_main]
zkvm::entrypoint!(main);

pub fn main() {
    let ledger_info_with_sig_bits = zkvm::io::read::<Vec<u8>>();
    let nbr_validators = zkvm::io::read::<usize>();

    let offset_validator_list: usize = (8 // epoch
        + 8 // round
        + 32 // id
        + 32 // executed state id
        + 8 // version
        + 8 // timestamp
        + 1 // Some
        + 8 // epoch
        + 1)
        * 8;
    // next byte
    let validators_list_len: usize = (1 + nbr_validators * (32 + 49 + 8)) * 8;
    // vec size + nbr_validators * (account address + pub key + voting power)
    let offset_ledger_info: usize = 8;
    // not taking the variant byte
    let ledger_info_len: usize = (8 // epoch
        + 8 // round
        + 32 // id
        + 32 // executed state id
        + 8 // version
        + 8 // timestamp
        + 1 // Some
        + 8 // epoch
        + 32)
        * 8
        + validators_list_len;
    // consensus data hash
    let offset_signature: usize = ledger_info_len + 8;
    // next byte
    let signature_len: usize = (1 + (nbr_validators + 7) / 8 + 1 + 1 + 96) * 8;

    // Extract bytes from the ledger info for given offsets and length
    let ledger_info_bits = ledger_info_with_sig_bits
        .iter()
        .skip(offset_ledger_info)
        .take(ledger_info_len)
        .copied()
        .collect::<Vec<u8>>();
    let signature_bits = ledger_info_with_sig_bits
        .iter()
        .skip(offset_signature)
        .take(signature_len)
        .copied()
        .collect::<Vec<u8>>();
    let validators_list_bits = ledger_info_with_sig_bits
        .iter()
        .skip(offset_validator_list)
        .take(validators_list_len)
        .copied()
        .collect::<Vec<u8>>();
    let epoch_bits = ledger_info_with_sig_bits
        .iter()
        .skip(offset_ledger_info)
        .take(64)
        .copied()
        .collect::<Vec<u8>>();

    zkvm::io::commit(&ledger_info_bits);
    zkvm::io::commit(&signature_bits);
    zkvm::io::commit(&validators_list_bits);
    zkvm::io::commit(&epoch_bits);
}
