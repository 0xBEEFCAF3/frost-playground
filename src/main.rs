use anyhow::Ok;
use bitcoin_hashes::Hash;
use bitcoincore_rpc::RpcApi;
use frost::{
    keys::{KeyPackage, PublicKeyPackage},
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
    Identifier, SigningPackage,
};
use frost_secp256k1_tr::{self as frost};
use rand::thread_rng;
use std::collections::BTreeMap;

const TEST_WALLET_NAME: &str = "frost-playground";
const MAX_SIGNERS: u16 = 3;
const MIN_SIGNERS: u16 = 2;
/// Extension trait for Frost verifying key (aggregate key)
pub trait VerifyingKeyExt: Into<frost::VerifyingKey> {
    fn to_secp_pk(self) -> Result<bitcoin::secp256k1::PublicKey, anyhow::Error> {
        let vk: frost::VerifyingKey = self.into();
        let pk = bitcoin::secp256k1::PublicKey::from_slice(vk.serialize().unwrap().as_slice())?;
        Ok(pk)
    }
}

impl VerifyingKeyExt for frost::VerifyingKey {}

fn dkg() -> anyhow::Result<
    (
        BTreeMap<Identifier, frost::keys::KeyPackage>,
        frost::keys::PublicKeyPackage,
    ),
    anyhow::Error,
> {
    let mut rng = thread_rng();

    let id1 = Identifier::try_from(1u16)?;
    let id2 = Identifier::try_from(2u16)?;
    let id3 = Identifier::try_from(3u16)?;

    // Round1
    let mut round1_for_p1 = BTreeMap::new();
    let mut round1_for_p2 = BTreeMap::new();
    let mut round1_for_p3 = BTreeMap::new();
    let (p1_round1_secret_package, p1_round1_package) =
        frost::keys::dkg::part1(id1, MAX_SIGNERS, MIN_SIGNERS, &mut rng)?;
    let (p2_round1_secret_package, p2_round1_package) =
        frost::keys::dkg::part1(id2, MAX_SIGNERS, MIN_SIGNERS, &mut rng)?;
    let (p3_round1_secret_package, p3_round1_package) =
        frost::keys::dkg::part1(id3, MAX_SIGNERS, MIN_SIGNERS, &mut rng)?;

    round1_for_p1.insert(id2, p2_round1_package.clone());
    round1_for_p1.insert(id3, p3_round1_package.clone());

    round1_for_p2.insert(id1, p1_round1_package.clone());
    round1_for_p2.insert(id3, p3_round1_package.clone());

    round1_for_p3.insert(id1, p1_round1_package.clone());
    round1_for_p3.insert(id2, p2_round1_package.clone());

    let mut round2_for_p1 = BTreeMap::new();
    let mut round2_for_p2 = BTreeMap::new();
    let mut round2_for_p3 = BTreeMap::new();
    let (p1_round2_secret_package, p1_round2_packages) =
        frost::keys::dkg::part2(p1_round1_secret_package, &round1_for_p1)?;

    let (p2_round2_secret_package, p2_round2_packages) =
        frost::keys::dkg::part2(p2_round1_secret_package, &round1_for_p2)?;

    let (p3_round2_secret_package, p3_round2_packages) =
        frost::keys::dkg::part2(p3_round1_secret_package, &round1_for_p3)?;

    round2_for_p1.insert(id2, p2_round2_packages.get(&id1).unwrap().clone());
    round2_for_p1.insert(id3, p3_round2_packages.get(&id1).unwrap().clone());

    round2_for_p2.insert(id1, p1_round2_packages.get(&id2).unwrap().clone());
    round2_for_p2.insert(id3, p3_round2_packages.get(&id2).unwrap().clone());

    round2_for_p3.insert(id1, p1_round2_packages.get(&id3).unwrap().clone());
    round2_for_p3.insert(id2, p2_round2_packages.get(&id3).unwrap().clone());

    let (key_package_p1, pubkey_package_p1) =
        frost::keys::dkg::part3(&p1_round2_secret_package, &round1_for_p1, &round2_for_p1)?;

    let (key_package_p2, _pubkey_package_p2) =
        frost::keys::dkg::part3(&p2_round2_secret_package, &round1_for_p2, &round2_for_p2)?;

    let (key_package_p3, _pubkey_package_p3) =
        frost::keys::dkg::part3(&p3_round2_secret_package, &round1_for_p3, &round2_for_p3)?;

    let mut keys = BTreeMap::new();
    keys.insert(id1, key_package_p1);
    keys.insert(id2, key_package_p2);
    keys.insert(id3, key_package_p3);

    // All the pubkey packages should be the same
    // Doesn't matter which one we use
    Ok((keys, pubkey_package_p1))
}

fn dealer() -> anyhow::Result<(BTreeMap<Identifier, KeyPackage>, PublicKeyPackage), anyhow::Error> {
    let mut rng = thread_rng();
    let (shares, pubkey_package) = frost::keys::generate_with_dealer(
        MAX_SIGNERS,
        MIN_SIGNERS,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )?;
    let mut key_packages = BTreeMap::new();

    for (id, share) in shares.iter() {
        let key_pkg: KeyPackage = share.to_owned().try_into().unwrap();
        key_packages.insert(*id, key_pkg);
    }
    Ok((key_packages, pubkey_package))
}

fn participant(
    key_package: &KeyPackage,
) -> anyhow::Result<(SigningNonces, SigningCommitments), anyhow::Error> {
    let mut rng = thread_rng();

    let signing_share = key_package.signing_share();
    let (nonces, commitments) = frost::round1::commit(signing_share, &mut rng);

    Ok((nonces, commitments))
}

fn participant_sign(
    nonces: &SigningNonces,
    signing_package: &SigningPackage,
    key_package: &KeyPackage,
) -> anyhow::Result<SignatureShare, anyhow::Error> {
    let signature_share = frost::round2::sign(&signing_package, nonces, key_package)?;

    Ok(signature_share)
}

/// connect to bitcoind
fn connect_to_bitcoind() -> bitcoincore_rpc::Client {
    let bitcoind_user = std::env::var("BITCOIND_USER").unwrap();
    let bitcoind_password = std::env::var("BITCOIND_PASSWORD").unwrap();
    // Assuming regtest
    bitcoincore_rpc::Client::new(
        "http://127.0.0.1:18443",
        bitcoincore_rpc::Auth::UserPass(bitcoind_user, bitcoind_password),
    )
    .unwrap()
}

fn psbt_to_sign(
    outpoint: bitcoin::OutPoint,
    prev_output: bitcoin::TxOut,
    amount_to_send: bitcoin::Amount,
    bitcoind_client: &impl bitcoincore_rpc::RpcApi,
) -> Result<bitcoin::psbt::Psbt, anyhow::Error> {
    let wallet_address = bitcoind_client
        .get_new_address(None, None)
        .unwrap()
        .assume_checked();
    let tx = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: outpoint,
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence(0),
            witness: bitcoin::Witness::new(),
        }],
        output: vec![bitcoin::TxOut {
            value: amount_to_send,
            script_pubkey: wallet_address.script_pubkey(),
        }],
    };

    let mut psbt = bitcoin::psbt::Psbt::from_unsigned_tx(tx)?;
    psbt.inputs[0].witness_utxo = Some(prev_output);

    Ok(psbt)
}

/// Calculate the sighash for a taproot keyspend
/// Using tapsighash type ALL
pub fn calculate_sighash(
    psbt: &bitcoin::psbt::Psbt,
    input_index: usize,
) -> Result<bitcoin::TapSighash, anyhow::Error> {
    let mut sighashcache = bitcoin::sighash::SighashCache::new(&psbt.unsigned_tx);

    let prevouts = psbt
        .inputs
        .iter()
        .map(|i| i.witness_utxo.as_ref().unwrap())
        .collect::<Vec<_>>();
    let sighash = sighashcache.taproot_key_spend_signature_hash(
        input_index,
        &bitcoin::sighash::Prevouts::All(&prevouts),
        bitcoin::TapSighashType::All,
    )?;

    Ok(sighash)
}

fn do_signing(
    keys: &BTreeMap<Identifier, KeyPackage>,
    pk_package: &PublicKeyPackage,
    psbt: &bitcoin::psbt::Psbt,
    merkle_root: Option<Vec<u8>>,
) -> Result<frost::Signature, anyhow::Error> {
    // Round 1
    let id1 = &Identifier::try_from(1u16).expect("valid identifier");
    let id2 = &Identifier::try_from(2u16).expect("valid identifier");
    let mut commitment_map = BTreeMap::new();
    let mut nonce_map = BTreeMap::new();

    let (nonces, commitments) = participant(keys.get(id1).unwrap()).unwrap();
    commitment_map.insert(id1.clone(), commitments);
    nonce_map.insert(id1.clone(), nonces);

    let (nonces, commitments) = participant(keys.get(id2).unwrap()).unwrap();
    commitment_map.insert(id2.clone(), commitments);
    nonce_map.insert(id2.clone(), nonces);

    // Signing round 2
    let sighash = calculate_sighash(psbt, 0)?;

    let sig_target = frost::SigningTarget::new(
        sighash.to_raw_hash().to_byte_array().as_slice(),
        frost::SigningParameters {
            tapscript_merkle_root: merkle_root,
        },
    );
    let signing_package = frost::SigningPackage::new(commitment_map, sig_target.clone());

    let mut signature_shares = BTreeMap::new();

    // Singer 1 sign
    let signature_share = participant_sign(
        &nonce_map.get(id1).unwrap(),
        &signing_package,
        keys.get(id1).unwrap(),
    )
    .unwrap();
    signature_shares.insert(id1.clone(), signature_share);

    // Singer 2 sign
    let signature_share = participant_sign(
        &nonce_map.get(id2).unwrap(),
        &signing_package,
        keys.get(id2).unwrap(),
    )
    .unwrap();
    signature_shares.insert(id2.clone(), signature_share);

    let group_signature =
        frost::aggregate(&signing_package, &signature_shares, &pk_package).unwrap();

    // Verify
    let is_signature_valid = pk_package
        .verifying_key()
        .verify(sig_target, &group_signature);

    println!("is_signature_valid: {:?}", is_signature_valid);
    assert!(is_signature_valid.is_ok());

    Ok(group_signature)
}

fn generate_script() -> bitcoin::ScriptBuf {
    // really dumb script that expect 1 on witness stack
    let script = bitcoin::Script::builder()
        .push_int(1)
        .push_opcode(bitcoin::opcodes::all::OP_EQUAL)
        .into_script();

    script
}

fn generate_taproot_spend_info(
    secp: &bitcoin::secp256k1::Secp256k1<impl bitcoin::secp256k1::Verification>,
    pk: &bitcoin::secp256k1::PublicKey,
) -> bitcoin::taproot::TaprootSpendInfo {
    let builder = bitcoin::taproot::TaprootBuilder::new()
        .add_leaf(0u8, generate_script())
        .expect("Couldn't add timelock leaf");

    let finalized_taproot = builder.finalize(&secp, pk.x_only_public_key().0).unwrap();

    finalized_taproot
}

/* TESTS */
fn test_key_spend(
    bitcoind_client: &impl bitcoincore_rpc::RpcApi,
    keys: &BTreeMap<Identifier, KeyPackage>,
    pk_package: &PublicKeyPackage,
) -> Result<(), anyhow::Error> {
    let bitcoind_wallet_address = bitcoind_client
        .get_new_address(None, None)
        .unwrap()
        .assume_checked();

    let signing_params = frost::SigningParameters {
        tapscript_merkle_root: None,
    };
    // This should be a x-only taptweaked key
    let effective_key = pk_package
        .verifying_key()
        .effective_key(&signing_params)
        .to_secp_pk()
        .unwrap();
    let key_spend_address = bitcoin::Address::p2tr_tweaked(
        bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(
            effective_key.x_only_public_key().0,
        ),
        bitcoin::KnownHrp::Regtest,
    );
    println!("Key spend address: {}", key_spend_address);

    let amount_to_recieve = bitcoin::Amount::from_sat(100_000);
    let txid = bitcoind_client
        .send_to_address(
            &key_spend_address,
            amount_to_recieve,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("valid send");
    // Lets confirm it
    bitcoind_client
        .generate_to_address(1, &bitcoind_wallet_address)
        .unwrap();
    println!("key spend txid: {}", txid);
    let tx = bitcoind_client
        .get_transaction(&txid, None)
        .unwrap()
        .transaction()
        .expect("get transaction");
    let vout = tx
        .output
        .iter()
        .position(|v| v.script_pubkey == key_spend_address.script_pubkey())
        .unwrap();
    let outpoint = bitcoin::OutPoint {
        txid,
        vout: vout as u32,
    };
    let txout = bitcoin::TxOut {
        value: amount_to_recieve,
        script_pubkey: key_spend_address.script_pubkey(),
    };
    let amount_to_send = bitcoin::Amount::from_sat(10_000);
    let mut psbt =
        psbt_to_sign(outpoint, txout, amount_to_send, bitcoind_client).expect("generate psbt");

    let group_signature = do_signing(&keys, &pk_package, &psbt, None)?;
    let secp_sig = bitcoin::secp256k1::schnorr::Signature::from_slice(
        &group_signature.serialize().expect("to serialize"),
    )
    .expect("generate secp signature");

    let hash_ty = bitcoin::sighash::TapSighashType::All;
    let sighash_type = bitcoin::psbt::PsbtSighashType::from(hash_ty);
    psbt.inputs[0].sighash_type = Some(sighash_type);
    psbt.inputs[0].tap_key_sig = Some(bitcoin::taproot::Signature {
        signature: secp_sig,
        sighash_type: hash_ty,
    });

    miniscript::psbt::PsbtExt::finalize_mut(&mut psbt, &bitcoin::secp256k1::Secp256k1::new())
        .expect("to finalize");

    let tx = psbt.extract_tx().expect("to extract tx");

    println!("key spend txid: {:?}", tx.compute_txid());

    bitcoind_client
        .send_raw_transaction(&tx.clone())
        .expect("Successfull broadcast");
    bitcoind_client
        .generate_to_address(1, &bitcoind_wallet_address)
        .unwrap();

    Ok(())
}

fn test_script_path_spend(
    bitcoind_client: &impl bitcoincore_rpc::RpcApi,
    pk_package: &frost::keys::PublicKeyPackage,
) -> Result<(), anyhow::Error> {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let bitcoind_wallet_address = bitcoind_client
        .get_new_address(None, None)
        .unwrap()
        .assume_checked();
    let taproot_spend_info =
        generate_taproot_spend_info(&secp, &pk_package.verifying_key().to_secp_pk().unwrap());

    let script = generate_script();
    let control_block = taproot_spend_info
        .control_block(&(script.clone(), bitcoin::taproot::LeafVersion::TapScript))
        .expect("valid tapscript buf and leaf version");

    let signing_params = frost::SigningParameters {
        tapscript_merkle_root: Some(
            taproot_spend_info
                .merkle_root()
                .expect("should have merkle root")
                .to_byte_array()
                .to_vec(),
        ),
    };
    // This should be a x-only taptweaked key
    let effective_key = pk_package
        .verifying_key()
        .effective_key(&signing_params)
        .to_secp_pk()
        .unwrap();
    let script_path_spend_address = bitcoin::Address::p2tr_tweaked(
        bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(
            effective_key.x_only_public_key().0,
        ),
        bitcoin::KnownHrp::Regtest,
    );
    println!("Key spend address: {}", script_path_spend_address);

    let amount_to_recieve = bitcoin::Amount::from_sat(100_000);
    let txid = bitcoind_client
        .send_to_address(
            &script_path_spend_address,
            amount_to_recieve,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("valid send");
    // Lets confirm it
    bitcoind_client
        .generate_to_address(1, &bitcoind_wallet_address)
        .unwrap();

    let tx = bitcoind_client
        .get_transaction(&txid, None)
        .unwrap()
        .transaction()
        .expect("get transaction");
    let vout = tx
        .output
        .iter()
        .position(|v| v.script_pubkey == script_path_spend_address.script_pubkey())
        .unwrap();
    let outpoint = bitcoin::OutPoint {
        txid,
        vout: vout as u32,
    };
    let txout = bitcoin::TxOut {
        value: amount_to_recieve,
        script_pubkey: script_path_spend_address.script_pubkey(),
    };
    let amount_to_send = bitcoin::Amount::from_sat(10_000);
    let mut psbt =
        psbt_to_sign(outpoint, txout, amount_to_send, bitcoind_client).expect("generate psbt");

    let hash_ty = bitcoin::sighash::TapSighashType::All;
    let sighash_type = bitcoin::psbt::PsbtSighashType::from(hash_ty);
    psbt.inputs[0].sighash_type = Some(sighash_type);
    psbt.inputs[0].tap_merkle_root = taproot_spend_info.merkle_root();
    let mut tap_scripts = BTreeMap::new();
    tap_scripts.insert(
        control_block.clone(),
        (script.clone(), bitcoin::taproot::LeafVersion::TapScript),
    );
    psbt.inputs[0].tap_scripts = tap_scripts;

    let wit = bitcoin::Witness::from(vec![vec![1], script.to_bytes(), control_block.serialize()]);
    psbt.inputs[0].final_script_witness = Some(wit);
    let tx = psbt.extract_tx().expect("to extract tx");
    println!("script path spend txid: {:?}", tx.compute_txid());

    bitcoind_client
        .send_raw_transaction(&tx.clone())
        .expect("Successfull broadcast");
    bitcoind_client
        .generate_to_address(1, &bitcoind_wallet_address)
        .unwrap();

    Ok(())
}

/* TESTS */
fn test_key_spend_with_tap_tweak(
    bitcoind_client: &impl bitcoincore_rpc::RpcApi,
    keys: &BTreeMap<Identifier, KeyPackage>,
    pk_package: &PublicKeyPackage,
) -> Result<(), anyhow::Error> {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let bitcoind_wallet_address = bitcoind_client
        .get_new_address(None, None)
        .unwrap()
        .assume_checked();

    let taproot_spend_info =
        generate_taproot_spend_info(&secp, &pk_package.verifying_key().to_secp_pk().unwrap());

    let merkel_root = taproot_spend_info
        .merkle_root()
        .expect("should have merkle root")
        .to_byte_array()
        .to_vec();

    let signing_params = frost::SigningParameters {
        tapscript_merkle_root: Some(merkel_root.clone()),
    };
    // This should be a x-only taptweaked key
    let effective_key = pk_package
        .verifying_key()
        .effective_key(&signing_params)
        .to_secp_pk()
        .unwrap();
    let address = bitcoin::Address::p2tr_tweaked(
        bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(
            effective_key.x_only_public_key().0,
        ),
        bitcoin::KnownHrp::Regtest,
    );
    println!("Key spend address: {}", address);

    let amount_to_recieve = bitcoin::Amount::from_sat(100_000);
    let txid = bitcoind_client
        .send_to_address(
            &address,
            amount_to_recieve,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("valid send");
    // Lets confirm it
    bitcoind_client
        .generate_to_address(1, &bitcoind_wallet_address)
        .unwrap();
    println!("key spend txid: {}", txid);
    let tx = bitcoind_client
        .get_transaction(&txid, None)
        .unwrap()
        .transaction()
        .expect("get transaction");
    let vout = tx
        .output
        .iter()
        .position(|v| v.script_pubkey == address.script_pubkey())
        .unwrap();
    let outpoint = bitcoin::OutPoint {
        txid,
        vout: vout as u32,
    };
    let txout = bitcoin::TxOut {
        value: amount_to_recieve,
        script_pubkey: address.script_pubkey(),
    };
    let amount_to_send = bitcoin::Amount::from_sat(10_000);
    let mut psbt =
        psbt_to_sign(outpoint, txout, amount_to_send, bitcoind_client).expect("generate psbt");

    let group_signature = do_signing(&keys, &pk_package, &psbt, Some(merkel_root))?;
    let secp_sig = bitcoin::secp256k1::schnorr::Signature::from_slice(
        &group_signature.serialize().expect("to serialize"),
    )
    .expect("generate secp signature");

    let hash_ty = bitcoin::sighash::TapSighashType::All;
    let sighash_type = bitcoin::psbt::PsbtSighashType::from(hash_ty);
    psbt.inputs[0].sighash_type = Some(sighash_type);
    psbt.inputs[0].tap_key_sig = Some(bitcoin::taproot::Signature {
        signature: secp_sig,
        sighash_type: hash_ty,
    });
    psbt.inputs[0].tap_merkle_root = taproot_spend_info.merkle_root();

    miniscript::psbt::PsbtExt::finalize_mut(&mut psbt, &secp)
        .expect("to finalize");

    let tx = psbt.extract_tx().expect("to extract tx");

    println!("key spend txid: {:?}", tx.compute_txid());

    bitcoind_client
        .send_raw_transaction(&tx.clone())
        .expect("Successfull broadcast");
    bitcoind_client
        .generate_to_address(1, &bitcoind_wallet_address)
        .unwrap();

    Ok(())
}

fn main() -> Result<(), anyhow::Error> {
    /* Test Setup */
    let bitcoind_client = connect_to_bitcoind();
    // Test connection
    let best_block_hash = bitcoind_client.get_best_block_hash();
    assert!(best_block_hash.is_ok());

    for wallet in bitcoind_client.list_wallets().unwrap() {
        let _ = bitcoind_client.unload_wallet(Some(&wallet));
    }
    // Load / create wallet
    if bitcoind_client
        .create_wallet(TEST_WALLET_NAME, None, None, None, None)
        .is_err()
    {
        bitcoind_client.load_wallet(TEST_WALLET_NAME).unwrap();
    }
    let bitcoind_wallet_address = bitcoind_client
        .get_new_address(None, None)
        .unwrap()
        .assume_checked();
    println!("bitcoind_wallet_address: {}", bitcoind_wallet_address);
    println!("Generating to address");
    bitcoind_client
        .generate_to_address(202, &bitcoind_wallet_address)
        .unwrap();

    let (dealer_keys, dealer_pk_package) = dealer().unwrap();
    let (dkg_keys, dkg_pk_package) = dkg().unwrap();

    /* TEST 1: Keyspend path with trusted setup */
    println!("TEST 1: Keyspend path with trusted setup");
    test_key_spend(&bitcoind_client, &dealer_keys, &dealer_pk_package)?;
    println!("TEST 1: Keyspend path with trusted setup successfu \n\n");

    /* TEST 2: Script path with trusted setup */
    println!("TEST 2: Script path with trusted setup");
    test_script_path_spend(&bitcoind_client, &dealer_pk_package)?;
    println!("TEST 2: Script path with trusted setup successful \n\n");

    /* TEST 3: Keyspend path with dkg setup */
    println!("TEST 3: Keyspend path with dkg setup");
    test_key_spend(&bitcoind_client, &dkg_keys, &dkg_pk_package)?;
    println!("TEST 3: Keyspend path with dkg setup successful \n\n");

    /* TEST 4: Script path with dkg setup */
    println!("TEST 4: Script path with dkg setup");
    test_script_path_spend(&bitcoind_client, &dkg_pk_package)?;
    println!("TEST 4: Script path with dkg setup successful \n\n");

    println!("TEST 5: Keyspend with a tap tweak with dkg setup");
    test_key_spend_with_tap_tweak(&bitcoind_client, &dkg_keys, &dkg_pk_package)?;
    println!("TEST 5: Keyspend with a tap tweak with dkg setup successful \n\n");

    println!("TEST 6: Keyspend with a tap tweak with dealer setup");
    test_key_spend_with_tap_tweak(&bitcoind_client, &dealer_keys, &dealer_pk_package)?;
    println!("TEST 6: Keyspend with a tap tweak with dealer setup successful \n\n");

    println!("all tests successful!");
    Ok(())
}
