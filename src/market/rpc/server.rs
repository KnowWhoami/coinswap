use std::sync::Arc;
use tokio::net::TcpListener;

use tokio::{
    io::{AsyncReadExt, BufReader},
    net::{tcp::ReadHalf, TcpStream}, //TcpListener
};

use crate::{
    maker::error::MakerError, market::directory::DirectoryServer, utill::send_message
};

use super::RpcMsgReq;
use super::RpcMsgResp;

pub async fn read_rpc_message(
    reader: &mut BufReader<ReadHalf<'_>>,
) -> Result<Option<RpcMsgReq>, MakerError> {
    let read_result = reader.read_u32().await;
    // If its EOF, return None
    if read_result
        .as_ref()
        .is_err_and(|e| e.kind() == std::io::ErrorKind::UnexpectedEof)
    {
        return Ok(None);
    }
    let length = read_result?;
    if length == 0 {
        return Ok(None);
    }
    let mut buffer = vec![0; length as usize];
    reader.read_exact(&mut buffer).await?;
    let message: RpcMsgReq = serde_cbor::from_slice(&buffer)?;
    Ok(Some(message))
}

async fn handle_request(mut socker: TcpStream) -> Result<(), MakerError> {
    let (socket_reader, mut socket_writer) = socker.split();
    let mut reader = BufReader::new(socket_reader);
    if let Some(rpc_request) = read_rpc_message(&mut reader).await? {
        match rpc_request {
            RpcMsgReq::Ping => {
                log::info!("RPC request received: {:?}", rpc_request);
                if let Err(e) = send_message(&mut socket_writer, &RpcMsgResp::Pong).await {
                    log::info!("Error sending RPC response {:?}", e);
                };
            }
        }
    }

    Ok(())
}

pub async fn start_rpc_server_thread(directory: Arc<DirectoryServer>) {
    let rpc_port = directory.rpc_port;
    let rpc_socket = format!("127.0.0.1:{}", rpc_port);
    let listener = TcpListener::bind(&rpc_socket).await.unwrap();
    log::info!(
        "[{}] RPC socket binding successful at {}",
        directory.rpc_port,
        rpc_socket
    );
    // read this
    tokio::spawn(async move {
        loop {
            let (socket, addrs) = listener.accept().await.unwrap();
            log::info!("Got RPC request from: {}", addrs);
            handle_request(socket).await.unwrap();
        }
    });
}


