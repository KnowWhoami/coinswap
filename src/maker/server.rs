//! The Coinswap Maker Server.
//!
//! This module includes all server side code for the coinswap maker.
//! The server maintains the thread pool for P2P Connection, Watchtower, Bitcoin Backend and RPC Client Request.
//! The server listens at two port 6102 for P2P, and 6103 for RPC Client request.

use std::{
    io::ErrorKind,
    net::{Ipv4Addr, TcpListener, TcpStream},
    path::Path,
    process::Child,
    sync::{
        atomic::{AtomicBool, Ordering::Relaxed},
        Arc,
    },
    thread::{self, sleep},
    time::Duration,
};

use bitcoin::{absolute::LockTime, Amount};
use bitcoind::bitcoincore_rpc::RpcApi;

#[cfg(feature = "tor")]
use socks::Socks5Stream;

pub(crate) use super::{
    api::{FIDELITY_CHECK_INTERVAL_SECS, RPC_PING_INTERVAL_SECS},
    Maker,
};

use crate::{
    error::NetError,
    maker::{
        api::{
            check_for_broadcasted_contracts, check_for_idle_states,
            restore_broadcasted_contracts_on_reboot, ConnectionState,
        },
        handlers::handle_message,
        rpc::start_rpc_server,
    },
    protocol::messages::{DnsMetadata, DnsRequest, FidelityProof, TakerToMakerMessage},
    utill::{get_tor_hostname, read_message, send_message, ConnectionType, HEART_BEAT_INTERVAL},
    wallet::WalletError,
};

#[cfg(feature = "tor")]
use crate::utill::monitor_log_for_completion;

use crate::maker::error::MakerError;

/// TODO: WRite about it.
pub(crate) const DIRECTORY_SERVERS_REFRESH_INTERVAL: Duration = Duration::from_secs(60 * 10); // 1 Block Interval

/// Fetches the Maker and DNS address, and sends maker address to the DNS server.
/// Depending upon ConnectionType and test/prod environment, different maker address and DNS addresses are returned.
/// Return the Maker address and an optional tor thread handle.
///
/// Tor thread is spawned only if ConnectionType=TOR and --feature=tor is enabled.
/// Errors if ConncetionType=TOR but, the tor feature is not enabled.
fn network_bootstrap(maker: Arc<Maker>) -> Result<(Option<Child>, String, String), MakerError> {
    let maker_port = maker.config.network_port;
    let (maker_address, dns_address, tor_handle) = match maker.config.connection_type {
        ConnectionType::CLEARNET => {
            let maker_address = format!("127.0.0.1:{}", maker_port);
            let dns_address = if cfg!(feature = "integration-test") {
                format!("127.0.0.1:{}", 8080)
            } else {
                maker.config.directory_server_address.clone()
            };

            (maker_address, dns_address, None)
        }
        #[cfg(feature = "tor")]
        ConnectionType::TOR => {
            let maker_socks_port = maker.config.socks_port;

            let tor_dir = maker.data_dir.join("tor");
            let tor_log_file = tor_dir.join("log");

            // Hard error if previous log file can't be removed, as monitor_log_for_completion doesn't work with existing file.
            // Tell the user to manually delete the file and restart.
            if tor_log_file.exists() {
                if let Err(e) = std::fs::remove_file(&tor_log_file) {
                    log::error!(
                        "Error removing previous tor log. Please delete the file and restart. | {:?}",
                        tor_log_file
                    );
                    return Err(e.into());
                } else {
                    log::info!("Previous tor log file deleted succesfully");
                }
            }

            let tor_handle = Some(crate::tor::spawn_tor(
                maker_socks_port,
                maker_port,
                tor_dir.to_str().unwrap().to_owned(),
            )?);

            log::info!(
                "[{}] waiting for tor setup to compelte.",
                maker.config.network_port
            );

            // TODO: move this function inside `spawn_tor` routine. `
            if let Err(e) =
                monitor_log_for_completion(&tor_log_file, "Bootstrapped 100% (done): Done")
            {
                log::error!(
                    "[{}] Error monitoring log file {:?}. Remove the file and restart again. | {}",
                    maker_port,
                    tor_log_file,
                    e
                );
                return Err(e.into());
            }

            log::info!("[{}] tor setup complete!", maker_port);

            let maker_hostname = get_tor_hostname(&tor_dir)?;
            let maker_address = format!("{}:{}", maker_hostname, maker.config.network_port);

            let dns_address = if cfg!(feature = "integration-test") {
                let dns_tor_dir = Path::new("/tmp/coinswap/dns/tor");
                let dns_hostname = get_tor_hostname(dns_tor_dir)?;
                format!("{}:{}", dns_hostname, 8080)
            } else {
                maker.config.directory_server_address.clone()
            };

            (maker_address, dns_address, tor_handle)
        }
    };

    Ok((tor_handle, maker_address, dns_address))
}

/// Manages the maker's fidelity bonds and ensures the DNS server is updated with the latest bond proof and maker address.
///
/// It performs the following operations:
/// 1. Redeems all expired fidelity bonds in the maker's wallet, if any are found.
/// 2. Creates a new fidelity bond if no valid bonds remain after redemption.
/// 3. Sends a POST request to the DNS server containing the maker's address and the proof of the fidelity bond
///    with the highest value.
fn manage_fidelity_bonds_and_update_dns(
    maker: &Maker,
    maker_address: &str,
    dns_address: &str,
) -> Result<(), MakerError> {
    maker.wallet.write()?.redeem_expired_fidelity_bonds()?;

    let proof = setup_fidelity_bond(&maker, maker_address)?.unwrap(); // TODO: Handle None case more gracefully if needed.

    log::info!(
        "Max offer size : {} sats",
        maker.get_wallet().read()?.store.offer_maxsize
    );

    let dns_metadata = DnsMetadata {
        url: maker_address.to_string(),
        proof,
    };

    let request = DnsRequest::Post {
        metadata: dns_metadata,
    };

    let port = maker.config.network_port;

    log::info!("[{}] Connecting to DNS: {}", port, dns_address);

    while !maker.shutdown.load(Relaxed) {
        let stream = match maker.config.connection_type {
            ConnectionType::CLEARNET => TcpStream::connect(dns_address),
            #[cfg(feature = "tor")]
            ConnectionType::TOR => Socks5Stream::connect(
                format!("127.0.0.1:{}", maker.config.socks_port),
                dns_address,
            )
            .map(|s| s.into_inner()),
        };

        match stream {
            Ok(mut stream) => match send_message(&mut stream, &request) {
                Ok(_) => {
                    log::info!(
                        "[{}] Successfully sent our address to DNS at {}",
                        port,
                        dns_address
                    );
                    break;
                }
                Err(e) => log::warn!(
                    "[{}] Failed to send our address to DNS server, retrying: {}",
                    port,
                    e
                ),
            },

            Err(e) => log::warn!(
                "[{}] Failed to establish TCP connection with DNS server, retrying: {}",
                port,
                e
            ),
        }

        // Wait for the configured interval before reattempting.
        thread::sleep(HEART_BEAT_INTERVAL);
    }

    Ok(())
}

/// Checks if the wallet already has fidelity bonds. if not, create the first fidelity bond.
fn setup_fidelity_bond(
    maker: &Maker,
    maker_address: &str,
) -> Result<Option<FidelityProof>, MakerError> {
    let highest_index = maker.get_wallet().read()?.get_highest_fidelity_index()?;
    let mut proof = maker.highest_fidelity_proof.write()?;

    if let Some(i) = highest_index {
        let wallet_read = maker.get_wallet().read()?;
        let (bond, _, _) = wallet_read.get_fidelity_bonds().get(&i).unwrap();

        let current_height = wallet_read
            .rpc
            .get_block_count()
            .map_err(WalletError::Rpc)? as u32;

        let highest_proof = maker
            .get_wallet()
            .read()?
            .generate_fidelity_proof(i, maker_address)?;

        log::info!(
            "Highest bond at outpoint {} |  index {} | Amount {:?} sats | Remaining Timelock for expiry : {:?} Blocks | Current Bond Value : {:?} sats",
            highest_proof.bond.outpoint,
            i,
            bond.amount.to_sat(),
            bond.lock_time.to_consensus_u32() - current_height,
            wallet_read.calculate_bond_value(i)?.to_sat()
        );

        *proof = Some(highest_proof);
    } else {
        // No bond in the wallet. Lets attempt to create one.
        let amount = Amount::from_sat(maker.config.fidelity_amount);
        let current_height = maker
            .get_wallet()
            .read()?
            .rpc
            .get_block_count()
            .map_err(WalletError::Rpc)? as u32;

        // Set 950 blocks locktime for test
        let locktime = if cfg!(feature = "integration-test") {
            LockTime::from_height(current_height + 950).map_err(WalletError::Locktime)?
        } else {
            LockTime::from_height(maker.config.fidelity_timelock + current_height)
                .map_err(WalletError::Locktime)?
        };

        let sleep_increment = 10;
        let mut sleep_multiplier = 0;
        log::info!("No active Fidelity Bonds found. Creating one.");
        log::info!("Fidelity value chosen = {:?} sats", amount.to_sat());
        log::info!("Fidelity Tx fee = 300 sats");
        log::info!(
            "Fidelity timelock {} blocks",
            maker.config.fidelity_timelock
        );
        while !maker.shutdown.load(Relaxed) {
            sleep_multiplier += 1;
            // sync the wallet
            maker.get_wallet().write()?.sync()?;

            let fidelity_result = maker
                .get_wallet()
                .write()?
                .create_fidelity(amount, locktime);

            match fidelity_result {
                // Wait for sufficient fund to create fidelity bond.
                // Hard error if fidelity still can't be created.
                Err(e) => {
                    if let WalletError::InsufficientFund {
                        available,
                        required,
                    } = e
                    {
                        log::warn!("Insufficient fund to create fidelity bond.");
                        let amount = required - available;
                        let addr = maker.get_wallet().write()?.get_next_external_address()?;

                        log::info!("Send at least {:.8} BTC to {:?} | If you send extra, that will be added to your wallet balance", amount, addr);

                        let total_sleep = sleep_increment * sleep_multiplier.min(10 * 60);
                        log::info!("Next sync in {:?} secs", total_sleep);
                        thread::sleep(Duration::from_secs(total_sleep));
                    } else {
                        log::error!(
                            "[{}] Fidelity Bond Creation failed: {:?}. Shutting Down Maker server",
                            maker.config.network_port,
                            e
                        );
                        return Err(e.into());
                    }
                }
                Ok(i) => {
                    log::info!(
                        "[{}] Successfully created fidelity bond",
                        maker.config.network_port
                    );
                    let highest_proof = maker
                        .get_wallet()
                        .read()?
                        .generate_fidelity_proof(i, maker_address)?;

                    *proof = Some(highest_proof);

                    // sync and save the wallet data to disk
                    maker.get_wallet().write()?.sync()?;
                    maker.get_wallet().read()?.save_to_disk()?;
                    break;
                }
            }
        }
    };

    Ok(proof.clone())
}

/// Keep checking if the Bitcoin Core RPC connection is live. Sets the global `accepting_client` flag as per RPC connection status.
///
/// This will not block. Once Core RPC connection is live, accepting_client will set as `true` again.
fn check_connection_with_core(maker: &Maker) -> Result<(), MakerError> {
    loop {
        if let Err(e) = maker.wallet.read()?.rpc.get_blockchain_info() {
            log::error!(
                "[{}] RPC Connection failed. Reattempting {}",
                maker.config.network_port,
                e
            );
        } else {
            break;
        }

        thread::sleep(HEART_BEAT_INTERVAL);
    }

    log::info!(
        "[{}] Bitcoin Core RPC connection is back online.",
        maker.config.network_port
    );

    Ok(())
}

/// Handle a single client connection.
fn handle_client(maker: &Arc<Maker>, stream: &mut TcpStream) -> Result<(), MakerError> {
    stream.set_nonblocking(false)?; // Block this thread until message is read.

    let mut connection_state = ConnectionState::default();

    while !maker.shutdown.load(Relaxed) {
        let mut taker_msg_bytes = Vec::new();
        match read_message(stream) {
            Ok(b) => taker_msg_bytes = b,
            Err(e) => {
                if let NetError::IO(e) = e {
                    if e.kind() == ErrorKind::UnexpectedEof {
                        log::info!("[{}] Connection ended.", maker.config.network_port);
                        break;
                    } else {
                        // For any other errors, report them
                        log::error!("[{}] Net Error: {}", maker.config.network_port, e);
                        continue;
                    }
                }
            }
        }

        let taker_msg: TakerToMakerMessage = serde_cbor::from_slice(&taker_msg_bytes)?;
        log::info!("[{}]  <=== {}", maker.config.network_port, taker_msg);

        let reply = handle_message(maker, &mut connection_state, taker_msg);

        match reply {
            Ok(reply) => {
                if let Some(message) = reply {
                    log::info!("[{}] ===> {} ", maker.config.network_port, message);
                    if let Err(e) = send_message(stream, &message) {
                        log::error!("Closing due to IO error in sending message: {:?}", e);
                        continue;
                    }
                } else {
                    continue;
                }
            }
            Err(err) => {
                match &err {
                    // Shutdown server if special behavior is set
                    MakerError::SpecialBehaviour(sp) => {
                        log::error!(
                            "[{}] Maker Special Behavior : {:?}",
                            maker.config.network_port,
                            sp
                        );
                        maker.shutdown.store(true, Relaxed);
                    }
                    e => {
                        log::error!(
                            "[{}] Internal message handling error occurred: {:?}",
                            maker.config.network_port,
                            e
                        );
                    }
                }
                return Err(err);
            }
        }
    }

    Ok(())
}

/// Starts the main Maker Server process.
///
/// This function initializes the Maker server by setting up network connections,
/// configuring the wallet with fidelity bond, and spawning necessary threads for:
/// - Checking Bitcoin Core connections.
/// - Monitoring idle client connections.
/// - Watching for broadcasted contract transactions.
/// - Running an RPC server for interacting with `maker-cli`.
///
/// It also handles incoming peer-to-peer (P2P) client connections in a loop, where
/// each connection spawns a dedicated handler thread.
///
/// The server continues to run until a shutdown signal is detected, at which point
/// it performs cleanup tasks, such as saving wallet data and terminating active Tor sessions.
pub fn start_maker_server(maker: Arc<Maker>) -> Result<(), MakerError> {
    log::info!("Starting Maker Server");
    // Initialize network connections.

    // Setup the wallet with fidelity bond.
    let port = maker.config.network_port;
    let network = maker.get_wallet().read()?.store.network;
    let balance = maker.get_wallet().read()?.spendable_balance()?;
    log::info!("[{}] Currency Network: {}", port, network);
    log::info!("[{}] Total Wallet Balance: {}", port, balance);

    let (_tor_thread, maker_address, dns_address) = network_bootstrap(maker.clone())?;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, maker.config.network_port))
        .map_err(NetError::IO)?;
    listener.set_nonblocking(true)?; // Needed to not block a thread waiting for incoming connection.

    if !maker.shutdown.load(Relaxed) {
        // 1. Idle Client connection checker thread.
        // This threads check idelness of peer in live swaps.
        // And takes recovery measure if the peer seems to have disappeared in middlle of a swap.
        let maker_clone = maker.clone();
        let idle_conn_check_thread = thread::Builder::new()
            .name("Idle Client Checker Thread".to_string())
            .spawn(move || {
                log::info!(
                    "[{}] Spawning Client connection status checker thread",
                    port
                );
                if let Err(e) = check_for_idle_states(maker_clone.clone()) {
                    log::error!("Failed checking client's idle state {:?}", e);
                    maker_clone.shutdown.store(true, Relaxed);
                }
            })?;
        maker.thread_pool.add_thread(idle_conn_check_thread);

        // 2. Watchtower thread.
        // This thread checks for broadcasted contract transactions, which usually means violation of the protocol.
        // When contract transaction detected in mempool it will attempt recovery.
        // This can get triggered even when contracts of adjacent hops are published. Implying the whole swap route is disrupted.
        let maker_clone = maker.clone();
        let contract_watcher_thread = thread::Builder::new()
            .name("Contract Watcher Thread".to_string())
            .spawn(move || {
                log::info!("[{}] Spawning contract-watcher thread", port);
                if let Err(e) = check_for_broadcasted_contracts(maker_clone.clone()) {
                    maker_clone.shutdown.store(true, Relaxed);
                    log::error!("Failed checking broadcasted contracts {:?}", e);
                }
            })?;
        maker.thread_pool.add_thread(contract_watcher_thread);

        // 3: The RPC server thread.
        // User for responding back to `maker-cli` apps.
        let maker_clone = maker.clone();
        let rpc_thread = thread::Builder::new()
            .name("RPC Thread".to_string())
            .spawn(move || {
                log::info!("[{}] Spawning RPC server thread", port);
                match start_rpc_server(maker_clone.clone()) {
                    Ok(_) => (),
                    Err(e) => {
                        log::error!("Failed starting rpc server {:?}", e);
                        maker_clone.shutdown.store(true, Relaxed);
                    }
                }
            })?;

        maker.thread_pool.add_thread(rpc_thread);

        sleep(HEART_BEAT_INTERVAL); // wait for 1 beat, to complete spawns of all the threads.
        maker.is_setup_complete.store(true, Relaxed);
        log::info!("[{}] Server Setup completed!! Use maker-cli to operate the server and the internal wallet.", maker.config.network_port);
    }

    // Check if recovery is needed.
    let (inc, out) = maker.wallet.read()?.find_unfinished_swapcoins();
    if !inc.is_empty() || !out.is_empty() {
        log::info!("Incomplete swaps detected in the wallet. Starting recovery");
        let maker_clone = maker.clone();
        restore_broadcasted_contracts_on_reboot(maker_clone.clone())?;
    }

    // The P2P Client connection loop.
    // Each client connection will spawn a new handler thread, which is added back in the global thread_pool.
    // This loop beats at `maker.config.heart_beat_interval_secs`
    let mut wait_time = 0;
    while !maker.shutdown.load(Relaxed) {
        if wait_time % RPC_PING_INTERVAL_SECS == 0 {
            if let Err(e) = check_connection_with_core(maker.as_ref()) {
                log::error!("[{}] Bitcoin Core connection check failed: {:?}", port, e);
                maker.shutdown.store(true, Relaxed);
            }
        }

        if wait_time % FIDELITY_CHECK_INTERVAL_SECS == 0 {
            if let Err(e) =
                manage_fidelity_bonds_and_update_dns(maker.as_ref(), &maker_address, &dns_address)
            {
                log::error!("[{}] Failed to either manage fidelity bonds or sending POST request to DNS: {:?}",port,e);
                maker.shutdown.store(true, Relaxed);
            }
            wait_time = 6;
        }

        match listener.accept() {
            Ok((mut stream, _)) => {
                log::info!("[{}] Received incoming connection", port);

                if let Err(e) = handle_client(&maker, &mut stream) {
                    log::error!("[{}] Error Handling client request {:?}", port, e);
                }
            }

            Err(e) => {
                if e.kind() != ErrorKind::WouldBlock {
                    log::error!("[{}] Error accepting incoming connection: {:?}", port, e);
                }
            }
        }

        wait_time += HEART_BEAT_INTERVAL.as_secs() as u32;
        sleep(HEART_BEAT_INTERVAL);
    }

    log::info!("[{}] Maker is shutting down.", port);
    maker.thread_pool.join_all_threads()?;

    #[cfg(feature = "tor")]
    if let Some(mut tor_thread) = _tor_thread {
        {
            if maker.config.connection_type == ConnectionType::TOR && cfg!(feature = "tor") {
                crate::tor::kill_tor_handles(&mut tor_thread);
            }
        }
    }

    log::info!("Shutdown wallet sync initiated.");
    maker.get_wallet().write()?.sync()?;
    log::info!("Shutdown wallet syncing completed.");
    maker.get_wallet().read()?.save_to_disk()?;
    log::info!("Wallet file saved to disk.");
    log::info!("Maker Server is shut down successfully");
    Ok(())
}
