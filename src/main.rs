use anyhow::Ok;
use bitcoin_hashes::Hash;
use bitcoincore_rpc::RpcApi;
use frost::{
    keys::{KeyPackage, PublicKeyPackage, SecretShare},
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
    Identifier, SigningPackage,
};
use frost_secp256k1_tr as frost;
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

fn dkg() -> anyhow::Result<(), anyhow::Error> {
    todo!("Implement DKG");
    // let mut rng = thread_rng();

    // let max_signers = 5;
    // let min_signers = 3;

    // // Ask the user which identifier they would like to use. You can create
    // // an identifier from a non-zero u16 or derive from an arbitrary string.
    // // Some fixed examples follow (each participant must choose a different identifier)
    // let participant_identifier = Identifier::try_from(7u16)?;

    // let (round1_secret_package, round1_package) =
    //     frost::keys::dkg::part1(participant_identifier, max_signers, min_signers, &mut rng)?;

    // let mut ids = HashMap::new();
    // ids.insert(participant_identifier, round1_package);
    // let (round2_secret_package, round2_packages) =
    //     frost::keys::dkg::part2(round1_secret_package, &ids)?;

    // let (key_package, pubkey_package) =
    //     frost::keys::dkg::part3(&round2_secret_package, &ids, &round2_packages)?;

    // println!("key_package: {:?}", key_package);
    // println!("pubkey_package: {:?}", pubkey_package);
    Ok(())
}

fn dealer() -> anyhow::Result<(BTreeMap<Identifier, SecretShare>, PublicKeyPackage), anyhow::Error>
{
    let mut rng = thread_rng();
    let (shares, pubkey_package) = frost::keys::generate_with_dealer(
        MAX_SIGNERS,
        MIN_SIGNERS,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )?;
    Ok((shares, pubkey_package))
}

fn participant(
    secret_share: &frost::keys::SecretShare,
) -> anyhow::Result<(SigningNonces, SigningCommitments), anyhow::Error> {
    let mut rng = thread_rng();

    let key_package: KeyPackage = secret_share.to_owned().try_into()?;
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
    keys: &BTreeMap<Identifier, SecretShare>,
    pk_package: &PublicKeyPackage,
    outpoint: bitcoin::OutPoint,
    bitcoind_client: &impl bitcoincore_rpc::RpcApi,
    txout: bitcoin::TxOut,
    amount_to_send: bitcoin::Amount,
) -> Result<(frost::Signature, bitcoin::psbt::Psbt), anyhow::Error> {
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
    let mut psbt = psbt_to_sign(
        outpoint,
        txout,
        amount_to_send,
        bitcoind_client,
    )?;
    let sighash = calculate_sighash(&psbt, 0)?;

    let sig_target = frost::SigningTarget::new(
        sighash.to_raw_hash().to_byte_array().as_slice(),
        frost::SigningParameters {
            tapscript_merkle_root: None,
        },
    );
    let signing_package = frost::SigningPackage::new(commitment_map, sig_target.clone());

    let mut signature_shares = BTreeMap::new();

    // Singer 1 sign
    let signature_share = participant_sign(
        &nonce_map.get(id1).unwrap(),
        &signing_package,
        &keys.get(id1).unwrap().to_owned().try_into().unwrap(),
    )
    .unwrap();
    signature_shares.insert(id1.clone(), signature_share);

    // Singer 2 sign
    let signature_share = participant_sign(
        &nonce_map.get(id2).unwrap(),
        &signing_package,
        &keys.get(id2).unwrap().to_owned().try_into().unwrap(),
    )
    .unwrap();
    signature_shares.insert(id2.clone(), signature_share);

    println!("signing package {:?}", signing_package);
    let group_signature =
        frost::aggregate(&signing_package, &signature_shares, &pk_package).unwrap();

    println!("group_signature: {:?}", group_signature);
     // Verify
     let is_signature_valid = pk_package
     .verifying_key()
     .verify(sig_target, &group_signature);

    println!("is_signature_valid: {:?}", is_signature_valid);
    assert!(is_signature_valid.is_ok());

    Ok((group_signature, psbt))
}

/* TESTS */
fn test_key_spend_with_trusted_setup(
    bitcoind_client: &impl bitcoincore_rpc::RpcApi,
) -> Result<(), anyhow::Error> {
    let bitcoind_wallet_address = bitcoind_client
        .get_new_address(None, None)
        .unwrap()
        .assume_checked();

    let keys = dealer().unwrap();
    let pk_package = keys.1;
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
    let (group_signature, mut psbt) = do_signing(
        &keys.0,
        &pk_package,
        outpoint,
        bitcoind_client,
        bitcoin::TxOut {
            value: amount_to_recieve,
            script_pubkey: key_spend_address.script_pubkey(),
        },
        bitcoin::Amount::from_sat(10_000),
    )?;
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

    println!("tx: {:?}", tx);
    println!("txid: {:?}", tx.compute_txid());

    bitcoind_client.send_raw_transaction(&tx.clone()).unwrap();
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
    /* TEST 1: Keyspend path with trusted setup */
    test_key_spend_with_trusted_setup(&bitcoind_client)?;

    Ok(())
}
