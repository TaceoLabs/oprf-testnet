use alloy::primitives::eip191_hash_message;
use alloy::signers::SignerSync;
use alloy::signers::k256::ecdsa::SigningKey;
use alloy::signers::k256::elliptic_curve::sec1::ToEncodedPoint;
use alloy::signers::local::PrivateKeySigner;
use ark_ff::PrimeField as _;
use eyre::Context;
use futures_util::{SinkExt, StreamExt};
use oprf_testnet_authentication::{
    AuthModule, basic::BasicTestNetRequestAuth, wallet_ownership::TestNetRequestAuth,
    wallet_ownership::zk,
};
use oprf_types_compat::{
    ShareEpoch,
    api::{OPRF_PROTOCOL_VERSION_HEADER, OprfRequest, OprfResponse},
    crypto::{OprfPublicKey, PartyId},
};
use rand::{CryptoRng, Rng};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use taceo_oprf::client::{
    self as oprf_client, Connector, NodeError, ServiceError, Uri, VerifiableOprfOutput,
};
use taceo_oprf::core::{
    ddlog_equality::shamir::{
        DLogCommitmentsShamir, DLogProofShareShamir, PartialDLogCommitmentsShamir,
    },
    oprf::{BlindedOprfResponse, BlindingFactor, client as oprf_core_client},
};
use tempfile::NamedTempFile;
use tokio::net::TcpStream;
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async_tls_with_config,
    tungstenite::{
        self, ClientRequestBuilder,
        protocol::{CloseFrame, frame::coding::CloseCode},
    },
};
use tracing::instrument;
use uuid::Uuid;
use x402_chain_eip155::{V1Eip155ExactClient, V2Eip155ExactClient};
use x402_types::{
    proto::{self, OriginalJson},
    scheme::client::X402SchemeClient,
    util::Base64Bytes,
};

type WebSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

#[instrument(level = "debug", skip_all)]
pub async fn basic_verifiable_oprf<R: Rng + CryptoRng>(
    nodes: &[String],
    threshold: usize,
    api_key: String,
    action: ark_babyjubjub::Fq,
    payment_signing_key: Option<SigningKey>,
    connector: Connector,
    rng: &mut R,
) -> eyre::Result<VerifiableOprfOutput> {
    tracing::info!("Running distributed OPRF with API only authentication");
    let start = Instant::now();
    let blinding_factor = BlindingFactor::rand(rng);
    let domain_separator = ark_babyjubjub::Fq::from_be_bytes_mod_order(b"OPRF TestNet");

    let auth = BasicTestNetRequestAuth { api_key };
    let nodes =
        oprf_client::to_oprf_uri_many(nodes, AuthModule::Basic).context("while parsing URIs")?;

    let verifiable_oprf_output = distributed_oprf_with_x402(
        &nodes,
        threshold,
        action,
        blinding_factor,
        domain_separator,
        auth,
        payment_signing_key.as_ref(),
        connector,
    )
    .await
    .context("during execution of the OPRF protocol")?;

    let elapsed = start.elapsed();
    tracing::info!("Total time taken for distributed OPRF with only API: {elapsed:?}");

    Ok(verifiable_oprf_output)
}

#[instrument(level = "debug", skip_all)]
pub async fn wallet_ownership_verifiable_oprf<R: Rng + CryptoRng>(
    nodes: &[String],
    threshold: usize,
    api_key: String,
    private_key: SigningKey,
    payment_signing_key: Option<SigningKey>,
    connector: Connector,
    rng: &mut R,
) -> eyre::Result<(VerifiableOprfOutput, Vec<u8>, Vec<u8>)> {
    tracing::info!("Running distributed OPRF with API and Proof authentication");
    let start = Instant::now();
    let blinding_factor = BlindingFactor::rand(rng);
    let domain_separator = ark_babyjubjub::Fq::from_be_bytes_mod_order(b"OPRF TestNet");

    let encoded_pubkey = private_key
        .verifying_key()
        .as_affine()
        .to_encoded_point(false);
    let x_affine = encoded_pubkey
        .x()
        .expect("should be possible to get x from publickey")
        .to_vec();
    let y_affine = encoded_pubkey
        .y()
        .expect("should be possible to get y from publickey")
        .to_vec();

    let signer = PrivateKeySigner::from_signing_key(private_key.clone());
    let query = ark_babyjubjub::Fq::from_be_bytes_mod_order(signer.address().as_ref());

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    let msg = format!("TACEO Oprf Input: {ts}");
    let msg_hash = eip191_hash_message(msg.as_bytes());
    let mut signature = signer.sign_hash_sync(&msg_hash)?.as_bytes().to_vec();

    _ = signature.pop();

    let (public_inputs, proof) = zk::compute_wallet_ownership_proof(
        &blinding_factor,
        &x_affine,
        &y_affine,
        &signature,
        msg_hash.as_ref(),
    )?;

    let auth = TestNetRequestAuth {
        public_inputs,
        proof,
        api_key,
    };

    let nodes = oprf_client::to_oprf_uri_many(nodes, AuthModule::WalletOwnership)
        .context("while parsing URIs")?;
    let payment_signing_key = payment_signing_key.as_ref().unwrap_or(&private_key);

    let verifiable_oprf_output = distributed_oprf_with_x402(
        &nodes,
        threshold,
        query,
        blinding_factor,
        domain_separator,
        auth,
        Some(payment_signing_key),
        connector,
    )
    .await
    .context("during execution of the OPRF protocol")?;

    tracing::debug!("Computing proof for the verifiable OPRF output..");
    let (public_inputs, proof) = zk::compute_nullifier_proof(
        verifiable_oprf_output.clone(),
        signature,
        msg_hash,
        &blinding_factor,
        x_affine,
        y_affine,
    )?;

    let vk = NamedTempFile::new().context("creating NamedTempFile for vk")?;
    std::fs::write(vk.path(), zk::VERIFIED_OPRF_PROOF_VK).context("writing VK to temp file")?;
    zk::verify_proof(&public_inputs, &proof, vk.path())?;

    let elapsed = start.elapsed();
    tracing::info!(
        "Total time taken for distributed OPRF with API and Proof authentication: {elapsed:?}",
    );

    Ok((verifiable_oprf_output, public_inputs, proof))
}

#[derive(Default)]
struct LocalOprfSessions {
    ws: Vec<WebSocketSession>,
    party_ids: Vec<PartyId>,
    commitments: Vec<PartialDLogCommitmentsShamir>,
    oprf_public_keys: Vec<OprfPublicKey>,
    epoch: ShareEpoch,
}

impl LocalOprfSessions {
    fn with_capacity(epoch: ShareEpoch, capacity: usize) -> Self {
        Self {
            epoch,
            ws: Vec::with_capacity(capacity),
            party_ids: Vec::with_capacity(capacity),
            commitments: Vec::with_capacity(capacity),
            oprf_public_keys: Vec::with_capacity(capacity),
        }
    }

    fn push(&mut self, ws: WebSocketSession, response: OprfResponse) -> Result<(), String> {
        let OprfResponse {
            commitments,
            party_id,
            oprf_pub_key_with_epoch,
        } = response;
        if let Some(position) = self
            .party_ids
            .iter()
            .position(|existing| *existing == party_id)
        {
            return Err(self.ws[position].service.clone());
        }
        self.ws.push(ws);
        self.party_ids.push(party_id);
        self.commitments.push(commitments);
        self.oprf_public_keys.push(oprf_pub_key_with_epoch.key);
        Ok(())
    }

    fn len(&self) -> usize {
        self.ws.len()
    }

    fn sort_by_party_id(&mut self) {
        let mut combined = self
            .ws
            .drain(..)
            .zip(self.party_ids.drain(..))
            .zip(self.commitments.drain(..))
            .zip(self.oprf_public_keys.drain(..))
            .map(|(((ws, party_id), commitments), oprf_public_key)| {
                (ws, party_id, commitments, oprf_public_key)
            })
            .collect::<Vec<_>>();
        combined.sort_by_key(|(_, party_id, _, _)| *party_id);
        for (ws, party_id, commitments, oprf_public_key) in combined {
            self.ws.push(ws);
            self.party_ids.push(party_id);
            self.commitments.push(commitments);
            self.oprf_public_keys.push(oprf_public_key);
        }
    }
}

struct WebSocketSession {
    service: String,
    inner: WebSocket,
}

impl WebSocketSession {
    async fn best_effort_close(&mut self, code: CloseCode, reason: impl Into<String>) {
        if let Err(err) = self
            .inner
            .close(Some(CloseFrame {
                code,
                reason: reason.into().into(),
            }))
            .await
        {
            tracing::trace!(
                "Received an error when trying to best effort close {}: {err:?}",
                self.service
            );
        }
    }

    async fn protocol_error<T>(&mut self, reason: T) -> NodeError
    where
        String: From<T>,
    {
        let reason = String::from(reason);
        self.best_effort_close(CloseCode::Unsupported, reason.clone())
            .await;
        NodeError::UnexpectedMessage { reason }
    }

    async fn new(
        endpoint: Uri,
        connector: Connector,
        payment_signing_key: Option<&SigningKey>,
    ) -> Result<Self, NodeError> {
        let service = endpoint
            .authority()
            .map_or_else(|| "unknown authority".to_string(), ToString::to_string);
        tracing::trace!("> sending request to {service}..");

        let inner = open_websocket(endpoint, connector, payment_signing_key).await?;
        Ok(Self { service, inner })
    }

    async fn send<Msg: serde::Serialize>(&mut self, msg: Msg) -> Result<(), NodeError> {
        let mut buf = Vec::new();
        ciborium::into_writer(&msg, &mut buf).expect("Can serialize msg");
        if let Err(err) = self.inner.send(tungstenite::Message::binary(buf)).await {
            self.best_effort_close(CloseCode::Error, "error during ws send")
                .await;
            Err(NodeError::WsError(Box::new(err)))
        } else {
            Ok(())
        }
    }

    async fn read<Msg: for<'de> serde::Deserialize<'de>>(&mut self) -> Result<Msg, NodeError> {
        let msg = match self.inner.next().await {
            Some(Ok(msg)) => msg,
            Some(Err(err)) => {
                self.best_effort_close(CloseCode::Error, err.to_string())
                    .await;
                return Err(NodeError::WsError(Box::new(err)));
            }
            None => {
                return Err(NodeError::UnexpectedMessage {
                    reason: "Server closed connection".into(),
                });
            }
        };

        match msg {
            tungstenite::Message::Binary(bytes) => {
                ciborium::from_reader(bytes.as_ref()).map_err(|_| NodeError::UnexpectedMessage {
                    reason: "could not parse message from server".into(),
                })
            }
            tungstenite::Message::Close(frame) => {
                self.best_effort_close(CloseCode::Normal, "").await;
                if let Some(frame) = frame
                    && frame.code != CloseCode::Normal
                {
                    let reason = if frame.reason.is_empty() {
                        format!(
                            "server closed websocket with code {}",
                            u16::from(frame.code)
                        )
                    } else {
                        format!(
                            "server closed websocket with code {}: {}",
                            u16::from(frame.code),
                            frame.reason
                        )
                    };
                    Err(NodeError::UnexpectedMessage { reason })
                } else {
                    Err(NodeError::UnexpectedMessage {
                        reason: "Server closed websocket".into(),
                    })
                }
            }
            tungstenite::Message::Text(_) => Err(self.protocol_error("text frame received").await),
            _ => Err(self.protocol_error("non-binary frame received").await),
        }
    }

    async fn graceful_close(mut self) {
        self.best_effort_close(CloseCode::Normal, "success").await;
    }
}

fn build_request(endpoint: Uri, payment_header: Option<(&str, String)>) -> ClientRequestBuilder {
    let mut request = ClientRequestBuilder::new(endpoint).with_header(
        OPRF_PROTOCOL_VERSION_HEADER.as_str(),
        env!("CARGO_PKG_VERSION"),
    );
    if let Some((header_name, header_value)) = payment_header {
        request = request.with_header(header_name, header_value);
    }
    request
}

async fn open_websocket(
    endpoint: Uri,
    connector: Connector,
    payment_signing_key: Option<&SigningKey>,
) -> Result<WebSocket, NodeError> {
    match connect_async_tls_with_config(
        build_request(endpoint.clone(), None),
        None,
        false,
        Some(connector.clone()),
    )
    .await
    {
        Ok((ws, _)) => Ok(ws),
        Err(tungstenite::Error::Http(response)) if response.status() == 402 => {
            let payment_required = deserialize_payment_required(&response).map_err(|err| {
                NodeError::Unknown(Box::new(std::io::Error::other(format!("x402: {err}"))))
            })?;
            tracing::info!(
                "Received 402 Payment Required during websocket handshake for {}",
                endpoint
            );
            let (header_name, header_value) =
                sign_payment_required(&payment_required, payment_signing_key)
                    .await
                    .map_err(|err| {
                        NodeError::Unknown(Box::new(std::io::Error::other(format!("x402: {err}"))))
                    })?;
            tracing::debug!("Retrying websocket handshake with {header_name}");
            connect_async_tls_with_config(
                build_request(endpoint, Some((header_name, header_value))),
                None,
                false,
                Some(connector),
            )
            .await
            .map(|(ws, _)| ws)
            .map_err(|err| match err {
                tungstenite::Error::Http(response) if response.status() == 402 => {
                    NodeError::Unknown(Box::new(std::io::Error::other(
                        "x402: payment was rejected during websocket handshake retry",
                    )))
                }
                other => NodeError::WsError(Box::new(other)),
            })
        }
        Err(err) => Err(NodeError::WsError(Box::new(err))),
    }
}

async fn sign_payment_required(
    payment_required: &proto::PaymentRequired,
    payment_signing_key: Option<&SigningKey>,
) -> eyre::Result<(&'static str, String)> {
    let payment_signing_key = payment_signing_key.ok_or_else(|| {
        eyre::eyre!(
            "received 402 Payment Required during websocket handshake, but no payment signer is configured; provide --payment-private-key"
        )
    })?;

    let signer = Arc::new(PrivateKeySigner::from_signing_key(
        payment_signing_key.clone(),
    ));
    let signed_payload = match payment_required {
        proto::PaymentRequired::V1(_) => {
            let client = V1Eip155ExactClient::new(signer);
            let candidate = client
                .accept(payment_required)
                .into_iter()
                .next()
                .ok_or_else(|| eyre::eyre!("no supported x402 V1 payment option was offered"))?;
            candidate.sign().await.map_err(|err| eyre::eyre!(err))?
        }
        proto::PaymentRequired::V2(_) => {
            let client = V2Eip155ExactClient::new(signer);
            let candidate = client
                .accept(payment_required)
                .into_iter()
                .next()
                .ok_or_else(|| eyre::eyre!("no supported x402 V2 payment option was offered"))?;
            candidate.sign().await.map_err(|err| eyre::eyre!(err))?
        }
    };

    let header_name = match payment_required {
        proto::PaymentRequired::V1(_) => "X-Payment",
        proto::PaymentRequired::V2(_) => "Payment-Signature",
    };
    Ok((header_name, signed_payload))
}

fn deserialize_payment_required(
    response: &tungstenite::http::Response<Option<Vec<u8>>>,
) -> eyre::Result<proto::PaymentRequired> {
    if let Some(header) = response.headers().get("Payment-Required") {
        let bytes = Base64Bytes::from(header.as_bytes())
            .decode()
            .map_err(|err| eyre::eyre!("failed to decode Payment-Required header: {err}"))?;
        let payment_required =
            serde_json::from_slice::<proto::v2::PaymentRequired<OriginalJson>>(&bytes)
                .context("failed to deserialize Payment-Required header as x402 V2")?;
        return Ok(proto::PaymentRequired::V2(payment_required));
    }

    let body = response
        .body()
        .as_deref()
        .ok_or_else(|| eyre::eyre!("missing HTTP response body for PaymentRequired"))?;

    serde_json::from_slice::<proto::v1::PaymentRequired<OriginalJson>>(body)
        .map(proto::PaymentRequired::V1)
        .or_else(|v1_err| {
            serde_json::from_slice::<proto::v2::PaymentRequired<OriginalJson>>(body)
                .map(proto::PaymentRequired::V2)
                .map_err(|v2_err| {
                    eyre::eyre!(
                        "failed to deserialize HTTP response as PaymentRequired: v1 error: {v1_err}; v2 error: {v2_err}"
                    )
                })
        })
}

#[instrument(level = "trace", skip(req, connector, payment_signing_key))]
async fn init_session<Auth: Clone + serde::Serialize>(
    service: Uri,
    req: OprfRequest<Auth>,
    connector: Connector,
    payment_signing_key: Option<&SigningKey>,
) -> Result<(WebSocketSession, OprfResponse), NodeError> {
    tracing::debug!("Trying to connect to service: {:?}", service.authority());
    let mut session = WebSocketSession::new(service, connector, payment_signing_key).await?;
    session.send(req).await?;
    let response = session.read::<OprfResponse>().await?;
    Ok((session, response))
}

#[instrument(level = "trace", skip_all)]
async fn finish_session(
    mut session: WebSocketSession,
    req: DLogCommitmentsShamir,
) -> Result<DLogProofShareShamir, NodeError> {
    session.send(req).await?;
    let resp = session.read().await?;
    session.graceful_close().await;
    Ok(resp)
}

#[instrument(level = "debug", skip_all)]
async fn finish_sessions(
    sessions: LocalOprfSessions,
    req: DLogCommitmentsShamir,
) -> Result<Vec<DLogProofShareShamir>, NodeError> {
    futures_util::future::try_join_all(
        sessions
            .ws
            .into_iter()
            .map(|session| finish_session(session, req.clone())),
    )
    .await
}

#[instrument(level = "debug", skip_all)]
async fn init_sessions<Auth: Clone + serde::Serialize + 'static>(
    services: &[Uri],
    threshold: usize,
    req: OprfRequest<Auth>,
    connector: Connector,
    payment_signing_key: Option<&SigningKey>,
) -> Result<LocalOprfSessions, Vec<NodeError>> {
    let payment_signing_key = payment_signing_key.cloned();
    let mut futures = futures_util::stream::FuturesUnordered::new();
    for service in services {
        let req = req.clone();
        let connector = connector.clone();
        let service = service.clone();
        let payment_signing_key = payment_signing_key.clone();
        futures.push(async move {
            init_session(
                service.clone(),
                req,
                connector,
                payment_signing_key.as_ref(),
            )
            .await
            .map_err(|err| (service, err))
        });
    }

    let mut epoch_session_map = HashMap::new();
    let mut session_errors = Vec::new();

    while let Some(result) = futures.next().await {
        match result {
            Ok((session, resp)) => {
                let epoch = resp.oprf_pub_key_with_epoch.epoch;
                let epoch_session = epoch_session_map
                    .entry(epoch)
                    .or_insert_with(|| LocalOprfSessions::with_capacity(epoch, threshold));
                tracing::debug!("received session for epoch: {epoch}");
                let service = session.service.clone();
                if let Err(duplicate_service) = epoch_session.push(session, resp) {
                    tracing::warn!("{duplicate_service} and {service} sent the same Party ID");
                    continue;
                }
                if epoch_session.len() == threshold {
                    let mut chosen_sessions = std::mem::take(epoch_session);
                    chosen_sessions.sort_by_party_id();
                    tracing::debug!(
                        "Initiated sessions {} with epoch {}",
                        chosen_sessions.len(),
                        chosen_sessions.epoch
                    );
                    return Ok(chosen_sessions);
                }
            }
            Err((service, err)) => {
                tracing::debug!(
                    "Got error response from {:?}: {err:?}",
                    service
                        .authority()
                        .map_or_else(|| "unknown service".to_owned(), ToString::to_string)
                );
                session_errors.push(err);
            }
        }
    }

    Err(session_errors)
}

fn service_error_to_eyre(service_error: ServiceError) -> eyre::Report {
    tracing::warn!("{service_error:?}");
    let message = service_error
        .msg
        .clone()
        .unwrap_or_else(|| "unknown message".to_owned());
    if service_error.is_auth() {
        eyre::eyre!("Authentication error from OPRF server: {message:?}")
    } else {
        eyre::eyre!(service_error)
    }
}

fn node_error_to_eyre(err: NodeError) -> eyre::Report {
    match err {
        NodeError::ServiceError(service_error) => service_error_to_eyre(service_error),
        NodeError::UnexpectedMessage { reason } => {
            eyre::eyre!("Server sent unexpected message: {reason}")
        }
        NodeError::WsError(error) => {
            if let Some(tungstenite::Error::Http(response)) =
                error.downcast_ref::<tungstenite::Error>()
            {
                eyre::eyre!(
                    "HTTP error during websocket handshake: {}",
                    response.status()
                )
            } else {
                eyre::eyre!("Networking errors - check your internet connection and try again")
            }
        }
        NodeError::Unknown(error) => {
            let message = error.to_string();
            if let Some(message) = message.strip_prefix("x402: ") {
                eyre::eyre!("x402 payment negotiation failed during websocket handshake: {message}")
            } else {
                eyre::eyre!("{message}")
            }
        }
        _ => eyre::eyre!("Unexpected node error"),
    }
}

fn aggregate_init_errors(threshold: usize, errors: Vec<NodeError>) -> eyre::Report {
    let mut service_errors = HashMap::new();
    let mut unexpected_messages = HashMap::new();
    let mut networking_count = 0usize;
    let mut fallback_errors = Vec::new();

    for err in errors {
        match err {
            NodeError::ServiceError(service_error) => {
                let count = service_errors
                    .entry(service_error.clone())
                    .or_insert(0usize);
                *count += 1;
                if *count >= threshold {
                    return service_error_to_eyre(service_error);
                }
                fallback_errors.push(NodeError::ServiceError(service_error));
            }
            NodeError::UnexpectedMessage { reason } => {
                let count = unexpected_messages.entry(reason.clone()).or_insert(0usize);
                *count += 1;
                if *count >= threshold {
                    return eyre::eyre!(
                        "Received an unexpected message from threshold many nodes: {reason}"
                    );
                }
                fallback_errors.push(NodeError::UnexpectedMessage { reason });
            }
            NodeError::WsError(error) => {
                networking_count += 1;
                fallback_errors.push(NodeError::WsError(error));
            }
            NodeError::Unknown(error) => {
                fallback_errors.push(NodeError::Unknown(error));
            }
            _ => {}
        }
    }

    if networking_count >= threshold {
        return eyre::eyre!("Networking errors - check your internet connection and try again");
    }

    if let Some(err) = fallback_errors.into_iter().next() {
        return node_error_to_eyre(err);
    }

    eyre::eyre!("Nodes could not agree on error")
}

fn generate_challenge_request(sessions: &LocalOprfSessions) -> DLogCommitmentsShamir {
    let contributing_parties = sessions
        .party_ids
        .iter()
        .map(|id| id.into_inner() + 1)
        .collect::<Vec<_>>();
    DLogCommitmentsShamir::combine_commitments(&sessions.commitments, contributing_parties)
}

#[instrument(level = "debug", skip_all, fields(request_id = tracing::field::Empty))]
async fn distributed_oprf_with_x402<Auth: Clone + serde::Serialize + 'static>(
    services: &[Uri],
    threshold: usize,
    query: ark_babyjubjub::Fq,
    blinding_factor: BlindingFactor,
    domain_separator: ark_babyjubjub::Fq,
    auth: Auth,
    payment_signing_key: Option<&SigningKey>,
    connector: Connector,
) -> eyre::Result<VerifiableOprfOutput> {
    if threshold == 0 || threshold > services.len() {
        eyre::bail!(
            "Invalid combination num_peers {} and threshold {}. Must be 0 < threshold <= num_peers",
            services.len(),
            threshold
        );
    }

    let services_dedup = services.iter().collect::<HashSet<_>>();
    eyre::ensure!(
        services_dedup.len() == services.len(),
        "Services must be unique"
    );

    let request_id = Uuid::new_v4();
    tracing::Span::current().record("request_id", request_id.to_string());
    tracing::debug!("starting with request id: {request_id}");

    let blinded_request = oprf_core_client::blind_query(query, blinding_factor);
    let oprf_req = OprfRequest {
        request_id,
        blinded_query: blinded_request.blinded_query(),
        auth,
    };

    tracing::debug!("initializing sessions at {} services", services.len());
    let sessions = init_sessions(
        services,
        threshold,
        oprf_req,
        connector,
        payment_signing_key,
    )
    .await
    .map_err(|errors| aggregate_init_errors(threshold, errors))?;

    let oprf_public_key = sessions
        .oprf_public_keys
        .first()
        .copied()
        .expect("at least one session");
    if !sessions
        .oprf_public_keys
        .iter()
        .all(|pk| *pk == oprf_public_key)
    {
        eyre::bail!("OPRF nodes returned different public keys");
    }

    let epoch = sessions.epoch;
    tracing::debug!("Will use epoch: {epoch}");
    tracing::debug!("compute the challenges for the services..");
    let challenge = generate_challenge_request(&sessions);

    tracing::debug!("finishing the sessions at the remaining services..");
    let responses = finish_sessions(sessions, challenge.clone())
        .await
        .map_err(node_error_to_eyre)?;

    let dlog_proof = oprf_client::verify_dlog_equality(
        request_id,
        oprf_public_key,
        &blinded_request,
        &responses,
        challenge.clone(),
    )
    .map_err(|err| eyre::eyre!(err))
    .context("verifying distributed dlog equality proof")?;

    let blinded_response = challenge.blinded_response();
    let prepared_blinding_factor = blinding_factor.prepare();
    let oprf_blinded_response = BlindedOprfResponse::new(blinded_response);
    let output = oprf_core_client::finalize_query(
        query,
        &oprf_blinded_response,
        &prepared_blinding_factor,
        domain_separator,
    );
    let unblinded_response = oprf_blinded_response.unblind_response(&prepared_blinding_factor);

    Ok(VerifiableOprfOutput {
        output,
        blinded_request: blinded_request.blinded_query(),
        blinded_response,
        dlog_proof,
        unblinded_response,
        oprf_public_key,
        epoch,
    })
}
