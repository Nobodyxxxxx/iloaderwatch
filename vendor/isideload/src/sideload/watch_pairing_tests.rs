use super::*;
use plist::{Dictionary, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn real_idevice_query_type_is_sent_and_parsed_over_fake_transport() {
    let (client, mut peer) = tokio::io::duplex(8192);
    let server = tokio::spawn(async move {
        let mut length = [0u8; 4];
        peer.read_exact(&mut length).await.unwrap();
        let mut bytes = vec![0; u32::from_be_bytes(length) as usize];
        peer.read_exact(&mut bytes).await.unwrap();
        let request: Dictionary = plist::from_bytes(&bytes).unwrap();
        assert_eq!(request.get("Request").and_then(Value::as_string), Some("QueryType"));
        assert!(!request.contains_key("PairRecord"));
        assert!(!request.contains_key("HostPrivateKey"));
        let mut reply = Dictionary::new();
        reply.insert("Type".into(), EXPECTED_LOCKDOWN_TYPE.into());
        let mut body = Vec::new();
        plist::to_writer_xml(&mut body, &reply).unwrap();
        peer.write_all(&(body.len() as u32).to_be_bytes()).await.unwrap();
        peer.write_all(&body).await.unwrap();
    });
    let mut connection = Idevice::new(Box::new(client), "synthetic-watch-test");
    let kind = stage("test", "lockdown_query_type", Duration::from_secs(2), connection.get_type()).await.unwrap();
    validate_lockdown_type(&kind).unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn open_but_silent_forwarded_socket_is_identified_before_pairing() {
    let (client, _silent_peer) = tokio::io::duplex(8192);
    let mut connection = Idevice::new(Box::new(client), "synthetic-watch-test");
    let failure = stage("test", "lockdown_query_type", Duration::from_millis(10), connection.get_type()).await.unwrap_err().to_string();
    assert!(failure.contains("[WatchStage:lockdown_query_type]"));
    assert!(!failure.contains("pair_build_or_trust"));
}

#[tokio::test]
async fn stage_timeout_has_a_bounded_name_without_any_private_payload() {
    let error = stage("test", "device_public_key", Duration::from_millis(1),
        std::future::pending::<Result<(), IdeviceError>>()).await.unwrap_err().to_string();
    assert!(error.contains("[WatchStage:device_public_key]"));
    assert!(error.contains("timed out"));
}

#[tokio::test]
async fn device_error_payload_does_not_leak_through_stage_diagnostics() {
    let error = stage("test", "pair_build_or_trust", Duration::from_secs(1), async {
        Err::<(), _>(IdeviceError::UnexpectedResponse("PRIVATE-CANARY-PAIRING-MATERIAL".into()))
    }).await.unwrap_err().to_string();
    assert!(error.contains("device error code"));
    assert!(!error.contains("PRIVATE-CANARY"));
}

#[test]
fn unexpected_type_is_not_echoed_and_does_not_count_as_lockdown() {
    let error = validate_lockdown_type("PRIVATE-CANARY-PEER-TYPE").unwrap_err().to_string();
    assert!(error.contains("lockdown_query_type"));
    assert!(!error.contains("PRIVATE-CANARY"));
    assert!(validate_lockdown_type(EXPECTED_LOCKDOWN_TYPE).is_ok());
}
