use soroban_sdk::{
    contract, contractimpl, contracttype, crypto::Hash, panic_with_error, Address, Bytes, BytesN,
    Env, Symbol,
};
use stellar_default_impl_macro::default_impl;
use stellar_ownable::{self as ownable, Ownable};
use stellar_ownable_macro::only_owner;
use stellar_upgradeable::UpgradeableInternal;
use stellar_upgradeable_macros::Upgradeable;
use crate::dependencies::*;
use crate::traits::*;

// ==================== Constants ====================

/// BTC native decimals.
const BTC_DECIMALS: u32 = 8;

/// Maximum decimals per token (shares, BTC, NAV).
const MAX_DECIMALS_PER_TOKEN: u32 = 18;

/// Maximum sum of decimals_a + decimals_b + decimals_c.
const MAX_DECIMALS_TOTAL: u32 = 38;

/// Allowed NAV drift in basis points (1% = 100 bps).
const NAV_DIFF_THRESHOLD_BPS: i128 = 100;

/// Basis points denominator (100% = 10000 bps).
const NAV_DIFF_BPS_DENOMINATOR: i128 = 10_000;

/// Maximum input length (in bytes) for hex encoding helper.
const MAX_OP_RETURN_HASH_LENGTH: usize = 32;

/// Bitcoin txid hex string length (UTF-8 bytes).
const BTC_TX_HASH_HEX_LENGTH: usize = 64;

/// StrKey address length for Soroban addresses.
const ADDRESS_STRKEY_LENGTH: usize = 56;

/// Max input lengths (bytes) to prevent abuse.
const MAX_MINT_NUM_STR_LENGTH: usize = 64;

// BIP-173/350 bech32/bech32m max length is 90 characters.
const MAX_BTC_RECEIVER_LENGTH: usize = 90;

/// Ethereum personal_sign V offset.
const ETHEREUM_V_OFFSET: u8 = 27;

const LEDGERS_PER_DAY: u32 = (24 * 3600) / 5;
const BTC_TX_HASH_TTL_THRESHOLD: u32 = 30 * LEDGERS_PER_DAY;
const BTC_TX_HASH_TTL_EXTEND_TO: u32 = 180 * LEDGERS_PER_DAY;

// ==================== Data Structures ====================

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BridgeDataKey {
    Admin,
    Token,
    Oracle,
    SignerPolicy(BytesN<65>), // SignerPolicy per signer for each secp256k1 key
    SignerMintCounter(BytesN<65>), // SignerMintCounter per signer for each secp256k1 key
    BTCTxHash(Bytes),
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
struct SignerPolicy {
    cap: i128,
    window_cap: i128,
    duration: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
struct SignerMintCounter {
    last_reset_time: u64,
    used_amount: i128,
}

#[derive(Upgradeable)]
#[contract]
pub struct SolvBTCBridge;

#[contractimpl]
impl SolvBTCBridge {
    pub fn __constructor(
        env: &Env,
        admin: Address,
        token: Address,
        oracle: Address,
    ) {
        // Validate decimals configuration to prevent unsafe exponentiation/overflow later.
        let shares_decimals = TokenClient::new(env, &token).decimals();
        let nav_decimals = OracleClient::new(env, &oracle).get_nav_decimals();
        Self::validate_decimals_config(env, shares_decimals, BTC_DECIMALS, nav_decimals);

        ownable::set_owner(env, &admin);
        env.storage().instance().set(&BridgeDataKey::Token, &token);
        env.storage().instance().set(&BridgeDataKey::Oracle, &oracle);
    }
}

#[contractimpl]
impl BridgeOperations for SolvBTCBridge {
    fn mint(
        env: Env,
        from: Address,
        signature: BytesN<65>,
        btc_tx_hash: Bytes,
        btc_amount: i128,
        btc_amount_str: Bytes,
        nav: i128,
        nav_str: Bytes,
    ) {
        from.require_auth();

        // 1. Validation
        if btc_amount <= 0 {
            panic_with_error!(&env, BridgeError::InvalidAmount);
        }
        if nav <= 0 {
            panic_with_error!(&env, BridgeError::InvalidNav);
        }

        if btc_tx_hash.len() != BTC_TX_HASH_HEX_LENGTH as u32 {
            panic_with_error!(&env, BridgeError::InvalidData);
        }
        if btc_amount_str.len() == 0 || btc_amount_str.len() > MAX_MINT_NUM_STR_LENGTH as u32 {
            panic_with_error!(&env, BridgeError::InvalidData);
        }
        if nav_str.len() == 0 || nav_str.len() > MAX_MINT_NUM_STR_LENGTH as u32 {
            panic_with_error!(&env, BridgeError::InvalidData);
        }

        // 2. Check if the BTC tx hash has been used
        if env
            .storage()
            .persistent()
            .has(&BridgeDataKey::BTCTxHash(btc_tx_hash.clone()))
        {
            panic_with_error!(&env, BridgeError::TxAlreadyUsed);
        }

        // 3. Get token address
        let token_address: Address = env.storage().instance().get(&BridgeDataKey::Token).unwrap();
      
        // 4. OP_RETURN Hash: Computed on-chain to prevent spoofing
        // keccak256("stellar" + token_address + user_address)
        let op_return_hash = Self::compute_op_return_hash(&env, &token_address, &from);
        let op_hash_hex = Self::op_return_hash_to_hex_string_bytes(&env, &op_return_hash);

        // 5. Verify Signature (EVM Personal Sign)
        let message = Self::build_mint_message(
            &env,
            &btc_tx_hash,
            &btc_amount_str,
            btc_amount,
            &op_hash_hex,
            &nav_str,
            nav,
            &from,
            &token_address,
        );

        // Use helper for personal_sign verification which includes hashing and recover
        let recovered_key = Self::verify_secp256k1_personal_sign_recover(&env, signature, message);

        // 6. NAV Validation
        Self::validate_nav_with_oracle(&env, nav);

        // 7. Check signer policy (cap + window cap)
        // Get signer policy
        let policy: SignerPolicy = env
            .storage()
            .instance()
            .get(&BridgeDataKey::SignerPolicy(recovered_key.clone()))
            .unwrap_or_else(|| panic_with_error!(&env, BridgeError::Unauthorized));

        // Check if signer policy is valid
        if policy.window_cap <= 0 || policy.duration == 0 {
            panic_with_error!(&env, BridgeError::InvalidSignerPolicy);
        }

        // Check if BTC amount exceeds signer cap
        if btc_amount > policy.cap {
            panic_with_error!(&env, BridgeError::SignerCapExceeded);
        }

        // Enforce signer window cap
        Self::enforce_signer_window_cap(&env, &recovered_key, &policy, btc_amount);

        // 8. Calculate Mint Amount
        let token_client = TokenClient::new(&env, &token_address);
        let shares_decimals = token_client.decimals();
        let btc_decimals = BTC_DECIMALS;

        let mint_amount = Self::calculate_mint_amount(
            &env,
            btc_amount,
            nav,
            btc_decimals,
            shares_decimals,
            Self::get_nav_decimals_internal(&env)
        );

        if mint_amount <= 0 {
            panic_with_error!(&env, BridgeError::InvalidAmount);
        }

        let tx_key = BridgeDataKey::BTCTxHash(btc_tx_hash.clone());
        env.storage().persistent().set(&tx_key, &true);
        env.storage()
            .persistent()
            .extend_ttl(&tx_key, BTC_TX_HASH_TTL_THRESHOLD, BTC_TX_HASH_TTL_EXTEND_TO);

        // Mint
        token_client.mint_from(&env.current_contract_address(), &from, &mint_amount);

        // Event
        env.events().publish(
            (Symbol::new(&env, "mint"), btc_tx_hash.clone(), from.clone()),
            MintEvent {
                btc_tx_hash,
                token_address,
                from: from.clone(),
                to: from,
                nav,
                btc_amount,
                mint_amount,
                op_return_hash,
            },
        );
    }

    fn redeem(
        env: Env,
        from: Address,
        amount: i128,
        receiver: Bytes,
    ) {
        from.require_auth();

        if amount <= 0 {
            panic_with_error!(&env, BridgeError::InvalidAmount);
        }

        if receiver.len() == 0 || receiver.len() > MAX_BTC_RECEIVER_LENGTH as u32 {
            panic_with_error!(env, BridgeError::InvalidAddress);
        }

        // Get NAV from Oracle
        let oracle_address: Address = env.storage().instance().get(&BridgeDataKey::Oracle).unwrap();
        let oracle_client = OracleClient::new(&env, &oracle_address);
        let current_nav = oracle_client.get_nav();
        let nav_decimals = oracle_client.get_nav_decimals();

        // Burn Tokens
        let token_address: Address = env.storage().instance().get(&BridgeDataKey::Token).unwrap();
        let token_client = TokenClient::new(&env, &token_address);
        token_client.burn_from(&env.current_contract_address(), &from, &amount);
        let shares_decimals = token_client.decimals();
        let btc_decimals = BTC_DECIMALS;

        // Calculate BTC Amount
        let btc_amount = Self::calculate_withdraw_amount(
            &env,
            amount,
            current_nav,
            shares_decimals,
            btc_decimals,
            nav_decimals
        );

        if btc_amount <= 0 {
            panic_with_error!(&env, BridgeError::InvalidAmount);
        }

        // Event
        env.events().publish(
            (Symbol::new(&env, "redeem"), receiver.clone(), from.clone()),
            RedeemEvent {
                token: token_address,
                user: from,
                btc_receiver: receiver,
                shares: amount,
                btc_amount,
                nav: current_nav,
            },
        );
    }
}

#[contractimpl]
impl BridgeAdmin for SolvBTCBridge {
    #[only_owner]
    fn set_signer_policy(env: Env, signer: BytesN<65>, cap: i128, window_cap: i128, duration: u64) {
        let signer_bytes = signer.to_array();
        // Uncompressed secp256k1 public key format: 0x04 || X(32) || Y(32)
        if signer_bytes[0] != 0x04 {
            panic_with_error!(&env, BridgeError::InvalidSignerKey);
        }

        if cap < 0 || window_cap <= 0 || duration == 0 || window_cap < cap {
            panic_with_error!(&env, BridgeError::InvalidSignerPolicy);
        }

        let policy = SignerPolicy {
            cap,
            window_cap,
            duration,
        };
        env.storage()
            .instance()
            .set(&BridgeDataKey::SignerPolicy(signer.clone()), &policy);
        env.events().publish(
            (Symbol::new(&env, "set_signer_policy"), signer.clone()),
            SetSignerPolicyEvent {
                admin: ownable::get_owner(&env).unwrap(),
                signer,
                cap,
                window_cap,
                duration,
            },
        );
    }

    #[only_owner]
    fn set_oracle(env: Env, oracle: Address) {
        // Validate decimals compatibility with the new oracle before updating
        let oracle_client = OracleClient::new(&env, &oracle);
        let nav_decimals = oracle_client.get_nav_decimals();
        let token: Address = env.storage().instance().get(&BridgeDataKey::Token).unwrap();
        let token_client = TokenClient::new(&env, &token);
        let shares_decimals = token_client.decimals();
        let btc_decimals = BTC_DECIMALS;
        Self::validate_decimals_config(&env, shares_decimals, btc_decimals, nav_decimals);

        let admin = ownable::get_owner(&env).unwrap();
        env.storage().instance().set(&BridgeDataKey::Oracle, &oracle);
        env.events().publish(
            (Symbol::new(&env, "set_oracle"), admin.clone()),
            SetOracleEvent {
                admin: admin.clone(),
                oracle: oracle.clone(),
            },
        );
    }
}

#[contractimpl]
impl BridgeQuery for SolvBTCBridge {
    fn get_signer_policy(env: Env, signer: BytesN<65>) -> (i128, i128, u64) {
        let policy: SignerPolicy = env
            .storage()
            .instance()
            .get(&BridgeDataKey::SignerPolicy(signer))
            .unwrap_or(SignerPolicy {
                cap: 0,
                window_cap: 0,
                duration: 0,
            });
        (policy.cap, policy.window_cap, policy.duration)
    }

    fn get_token(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&BridgeDataKey::Token)
            .unwrap()
    }

    fn get_oracle(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&BridgeDataKey::Oracle)
            .unwrap()
    }
}

#[default_impl]
#[contractimpl]
impl Ownable for SolvBTCBridge {}

impl UpgradeableInternal for SolvBTCBridge {
    fn _require_auth(e: &Env, operator: &Address) {
        operator.require_auth();
        let owner = ownable::get_owner(e).unwrap();
        if *operator != owner {
            panic_with_error!(e, BridgeError::Unauthorized);
        }
    }
}

// ==================== Private Helper Functions ====================

impl SolvBTCBridge {
    /// Recover public key from personal_sign signature
    fn verify_secp256k1_personal_sign_recover(
        env: &Env,
        signature: BytesN<65>,
        message: Bytes,
    ) -> BytesN<65> {
        let msg_hash = Self::personal_sign_hash(env, &message);

        let sig_array = signature.to_array();
        let mut rs_array = [0u8; 64];
        rs_array.copy_from_slice(&sig_array[0..64]);
        let rs_bytes_n = BytesN::from_array(env, &rs_array);

        let v_byte = sig_array[64];
        let recovery_id = if v_byte >= ETHEREUM_V_OFFSET {
            (v_byte - ETHEREUM_V_OFFSET) as u32
        } else {
            v_byte as u32
        };

        if recovery_id > 1 {
            panic_with_error!(env, BridgeError::InvalidSignature);
        }

        env.crypto().secp256k1_recover(&msg_hash, &rs_bytes_n, recovery_id)
    }

    /// personal_sign Hash: keccak256("\x19Ethereum Signed Message:\n" + len(msg) + msg)
    fn personal_sign_hash(env: &Env, message: &Bytes) -> Hash<32> {
        let mut eth_msg = Bytes::new(env);
        eth_msg.append(&Bytes::from_slice(
            env,
            b"\x19Ethereum Signed Message:\n",
        ));
        eth_msg.append(&Self::u32_to_ascii_bytes(env, message.len()));
        eth_msg.append(message);

        env.crypto().keccak256(&eth_msg)
    }

    /// Compute op_return hash
    pub(crate) fn compute_op_return_hash(
        env: &Env,
        token: &Address,
        user: &Address,
    ) -> Bytes {
        let mut op_input = Bytes::new(env);
        op_input.append(&Bytes::from_slice(env, b"stellar"));
        op_input.append(&Self::address_to_bytes(env, token));
        op_input.append(&Self::address_to_bytes(env, user));
        env.crypto().keccak256(&op_input).into()
    }

    /// Build mint message
    pub(crate) fn build_mint_message(
        env: &Env,
        btc_tx_hash: &Bytes,
        btc_amount_str: &Bytes,
        btc_amount: i128,
        op_return_hash_hex: &Bytes,
        nav_str: &Bytes,
        nav: i128,
        user: &Address,
        token: &Address,
    ) -> Bytes {
        let mut message = Bytes::new(env);
        message.append(&Bytes::from_slice(
            env,
            b"[BTC-Mint-Stellar-SolvBTC]\n\nBTC TX Hash:\n",
        ));
        message.append(btc_tx_hash);
        message.append(&Bytes::from_slice(env, b"\n\nBTC Amount:\n"));
        message.append(btc_amount_str);
        message.append(&Bytes::from_slice(env, b"\n("));
        message.append(&Self::i128_to_ascii_bytes(env, btc_amount));
        message.append(&Bytes::from_slice(env, b")\n\nOP_RETURN Hash:\n"));
        message.append(op_return_hash_hex);
        message.append(&Bytes::from_slice(env, b"\n\nNAV:\n"));
        message.append(nav_str);
        message.append(&Bytes::from_slice(env, b"\n("));
        message.append(&Self::i128_to_ascii_bytes(env, nav));
        message.append(&Bytes::from_slice(
            env,
            b")\n\nUser Address:\n",
        ));
        message.append(&Self::address_to_bytes(env, user));
        message.append(&Bytes::from_slice(
            env,
            b"\n\nToken Address:\n",
        ));
        message.append(&Self::address_to_bytes(env, token));
        message
    }

    /// Validate decimals configuration
    pub(crate) fn validate_decimals_config(env: &Env, decimals_a: u32, decimals_b: u32, decimals_c: u32) {
        if decimals_a > MAX_DECIMALS_PER_TOKEN
            || decimals_b > MAX_DECIMALS_PER_TOKEN
            || decimals_c > MAX_DECIMALS_PER_TOKEN
        {
            panic_with_error!(env, BridgeError::InvalidDecimals);
        }
        if (decimals_a + decimals_b + decimals_c) > MAX_DECIMALS_TOTAL {
            panic_with_error!(env, BridgeError::InvalidDecimals);
        }
    }

     /// Validate that provided NAV is close enough to oracle NAV (<= 1% diff).
    fn validate_nav_with_oracle(env: &Env, provided_nav: i128) {
        // Since the estimated APR is within 5%, and the time interval between users withdraw
        // requests and claims will not exceed 2 months, we limit the NAV difference between
        // these two operations to no more than 1%.
        let oracle_address: Address = env
            .storage()
            .instance()
            .get(&BridgeDataKey::Oracle)
            .unwrap();
        let oracle_client = OracleClient::new(env, &oracle_address);
        let realtime_nav = oracle_client.get_nav();

        if realtime_nav <= 0 {
            panic_with_error!(env, BridgeError::InvalidNav);
        }

        let diff = provided_nav
            .checked_sub(realtime_nav)
            .and_then(|d| d.checked_abs())
            .unwrap_or_else(|| panic_with_error!(env, BridgeError::InvalidNav));

        let limit = realtime_nav
            .checked_mul(NAV_DIFF_THRESHOLD_BPS)
            .and_then(|x| x.checked_div(NAV_DIFF_BPS_DENOMINATOR))
            .unwrap_or_else(|| panic_with_error!(env, BridgeError::InvalidNav));

        if diff > limit {
            panic_with_error!(env, BridgeError::NavOutOfRange);
        }
    }

    fn enforce_signer_window_cap(
        env: &Env,
        signer: &BytesN<65>,
        policy: &SignerPolicy,
        amount: i128,
    ) {
        let now = env.ledger().timestamp();
        let key = BridgeDataKey::SignerMintCounter(signer.clone());
        let mut counter: SignerMintCounter = env.storage().instance().get(&key).unwrap_or(
            SignerMintCounter {
                last_reset_time: now,
                used_amount: 0,
            },
        );

        if now < counter.last_reset_time
            || now
                .checked_sub(counter.last_reset_time)
                .map(|elapsed| elapsed >= policy.duration)
                .unwrap_or(true)
        {
            counter.last_reset_time = now;
            counter.used_amount = 0;
        }

        let new_used = counter
            .used_amount
            .checked_add(amount)
            .unwrap_or_else(|| panic_with_error!(env, BridgeError::InvalidAmount));

        if new_used > policy.window_cap {
            panic_with_error!(env, BridgeError::SignerWindowCapExceeded);
        }

        counter.used_amount = new_used;
        env.storage().instance().set(&key, &counter);
    }

    /// Get NAV decimals from Oracle
    fn get_nav_decimals_internal(env: &Env) -> u32 {
        let oracle_address: Address = env.storage().instance().get(&BridgeDataKey::Oracle).unwrap();
        OracleClient::new(env, &oracle_address).get_nav_decimals()
    }
    
    /// Calculate mint amount
    pub(crate) fn calculate_mint_amount(
        env: &Env,
        deposit_amount: i128,
        nav: i128,
        currency_decimals: u32,
        shares_decimals: u32,
        nav_decimals: u32,
    ) -> i128 {
        Self::validate_decimals_config(env, shares_decimals, currency_decimals, nav_decimals);

        if nav <= 0 {
            panic_with_error!(env, BridgeError::InvalidNav);
        }

        let common_factor = shares_decimals.min(currency_decimals);
        let nav_scale = 10_i128.pow(nav_decimals);
        let (scale_num, scale_den) = if shares_decimals >= currency_decimals {
            (10_i128.pow(shares_decimals - common_factor), 1_i128)
        } else {
            (1_i128, 10_i128.pow(currency_decimals - common_factor))
        };

        let numerator = deposit_amount
            .checked_mul(scale_num)
            .and_then(|x| x.checked_mul(nav_scale))
            .unwrap_or_else(|| panic_with_error!(env, BridgeError::InvalidAmount));
        let denominator = nav
            .checked_mul(scale_den)
            .unwrap_or_else(|| panic_with_error!(env, BridgeError::InvalidAmount));

        let minted = numerator
            .checked_div(denominator)
            .unwrap_or_else(|| panic_with_error!(env, BridgeError::InvalidAmount));

        minted
    }

    /// Calculate withdraw amount
    pub(crate) fn calculate_withdraw_amount(
        env: &Env,
        shares: i128,
        nav: i128,
        shares_token_decimals: u32,
        withdraw_token_decimals: u32,
        nav_decimals: u32,
    ) -> i128 {
        Self::validate_decimals_config(env, shares_token_decimals, withdraw_token_decimals, nav_decimals);

        if nav <= 0 {
            panic_with_error!(env, BridgeError::InvalidNav);
        }

        let common_factor = shares_token_decimals.min(withdraw_token_decimals);
        let nav_scale = 10_i128.pow(nav_decimals);

        let scaled_shares = if withdraw_token_decimals >= shares_token_decimals {
            let scale = 10_i128.pow(withdraw_token_decimals - common_factor);
            shares
                .checked_mul(scale)
                .unwrap_or_else(|| panic_with_error!(env, BridgeError::InvalidAmount))
        } else {
            let scale = 10_i128.pow(shares_token_decimals - common_factor);
            shares
                .checked_div(scale)
                .unwrap_or_else(|| panic_with_error!(env, BridgeError::InvalidAmount))
        };

        let amount = scaled_shares
            .checked_mul(nav)
            .and_then(|x| x.checked_div(nav_scale))
            .unwrap_or_else(|| panic_with_error!(env, BridgeError::InvalidAmount));

        amount
    }

    /// Convert op_return hash to hex string bytes
    pub(crate) fn op_return_hash_to_hex_string_bytes(env: &Env, data: &Bytes) -> Bytes {
        let len = data.len() as usize;
        if len > MAX_OP_RETURN_HASH_LENGTH {
            panic_with_error!(env, BridgeError::InvalidAmount);
        }
        let mut buf = [0u8; MAX_OP_RETURN_HASH_LENGTH];
        data.copy_into_slice(&mut buf[..len]);

        let mut hex_buf = [0u8; MAX_OP_RETURN_HASH_LENGTH * 2];
        let hex_chars = b"0123456789abcdef";

        for i in 0..len {
            let b = buf[i];
            hex_buf[i * 2] = hex_chars[(b >> 4) as usize];
            hex_buf[i * 2 + 1] = hex_chars[(b & 0x0F) as usize];
        }

        Bytes::from_slice(env, &hex_buf[..len * 2])
    }

    /// Convert u32 to ascii bytes
    fn u32_to_ascii_bytes(env: &Env, mut n: u32) -> Bytes {
        if n == 0 {
            return Bytes::from_slice(env, b"0");
        }
        let mut buf = [0u8; 10];
        let mut i = 10;
      
        while n > 0 {
            i -= 1;
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
        Bytes::from_slice(env, &buf[i..])
    }

    /// Convert address to bytes
    pub(crate) fn address_to_bytes(env: &Env, addr: &Address) -> Bytes {
        // Soroban address are 56-char StrKey strings.
        let s = addr.to_string();
        let len = s.len() as usize;
        if len != ADDRESS_STRKEY_LENGTH {
            panic_with_error!(env, BridgeError::InvalidAddress);
        }
        let mut tmp = [0u8; ADDRESS_STRKEY_LENGTH];
        s.copy_into_slice(&mut tmp[..len]);
        Bytes::from_slice(env, &tmp[..len])
    }

    /// Convert i128 to ascii bytes
    fn i128_to_ascii_bytes(env: &Env, mut n: i128) -> Bytes {
        if n == 0 {
            return Bytes::from_slice(env, b"0");
        }
        let mut buf = [0u8; 40];
        let mut i = 40;
        let is_neg = n < 0;
       
        if is_neg {
            n = -n;
        }

        while n > 0 {
            i -= 1;
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }

        if is_neg {
            i -= 1;
            buf[i] = b'-';
        }

        Bytes::from_slice(env, &buf[i..])
    }
}
