use super::*;

fn progress(percent: u64) -> Dictionary {
    let mut inner = Dictionary::new();
    inner.insert("PercentComplete".into(), Value::Integer(percent.into()));
    inner.insert("Status".into(), Value::String("Installing".into()));
    let mut response = Dictionary::new();
    response.insert("InstallProgressDict".into(), Value::Dictionary(inner));
    response
}

fn failure(description: &str) -> Dictionary {
    let mut error = Dictionary::new();
    error.insert("Error".into(), Value::String("ApplicationVerificationFailed".into()));
    error.insert("ErrorDescription".into(), Value::String(description.into()));
    error
}

#[test]
fn only_known_coordinator_conflicts_are_retryable() {
    for message in [
        "Error Domain=IXErrorDomain Code=48 \"busy\"",
        "ixerrordomain code=48: coordinator conflict",
        "A coordinated install exists for this identity",
        "process-scoped coordinator is scoped to a different process",
    ] {
        assert!(is_coordinator_message(message), "{message}");
    }
    for message in [
        "IXErrorDomain Code=480",
        "IXErrorDomain Code=49",
        "MIInstallerErrorDomain Code=48",
        "ApplicationVerificationFailed: signature is invalid",
        "DeviceLocked",
        "connection timed out",
        "process-scoped coordinator",
    ] {
        assert!(!is_coordinator_message(message), "{message}");
    }
}

#[test]
fn coordinator_error_is_found_through_report_context() {
    let error: Report = report!("Error Domain=IXErrorDomain Code=48").context("Watch transfer failed").into();
    assert!(is_watch_coordinator_conflict(&error));
    let signing_error: Report = report!("signature verification failed").context("Watch transfer failed").into();
    assert!(!is_watch_coordinator_conflict(&signing_error));
}

#[test]
fn retry_budget_and_backoff_are_bounded() {
    let expected = [400, 800, 1600, 2500, 2500, 2500];
    for (index, millis) in expected.into_iter().enumerate() {
        assert_eq!(watch_retry_delay(index + 1, true), Some(Duration::from_millis(millis)));
        assert_eq!(watch_retry_delay(index + 1, false), None);
    }
    assert_eq!(watch_retry_delay(0, true), None);
    assert_eq!(watch_retry_delay(WATCH_INSTALL_ATTEMPTS, true), None);
    assert_eq!(watch_retry_delay(usize::MAX, true), None);
}

#[test]
fn crc32_matches_standard_vectors() {
    assert_eq!(crc32_ieee(b""), 0);
    assert_eq!(crc32_ieee(b"123456789"), 0xcbf4_3926);
    assert_eq!(crc32_ieee(b"The quick brown fox jumps over the lazy dog"), 0x414f_a339);
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

#[test]
fn local_zip_header_is_stored_with_little_endian_crc_and_sizes() {
    let name = "Payload/Watch.app/_CodeSignature/CodeResources";
    let body = b"signature resource bytes must remain unchanged";
    let header = zip_header(name, body.len() as u32, crc32_ieee(body)).unwrap();
    assert_eq!(&header[..4], &[0x50, 0x4b, 0x03, 0x04]);
    assert_eq!(u16_at(&header, 4), 20);
    assert_eq!(u16_at(&header, 6), 0x0800);
    assert_eq!(u16_at(&header, 8), 0); // no compression/re-signing/transformation
    assert_eq!(u32_at(&header, 14), crc32_ieee(body));
    assert_eq!(u32_at(&header, 18), body.len() as u32);
    assert_eq!(u32_at(&header, 22), body.len() as u32);
    assert_eq!(u16_at(&header, 26) as usize, name.len());
    assert_eq!(u16_at(&header, 28) as usize, ZIP_EXTRA.len());
    assert_eq!(&header[30..30 + name.len()], name.as_bytes());
    assert_eq!(&header[30 + name.len()..], ZIP_EXTRA);
    assert_eq!(CENTRAL_DIRECTORY_HEADER, &[0x50, 0x4b, 0x01, 0x02]);
}

#[test]
fn empty_file_and_unicode_names_have_valid_headers() {
    let name = "Payload/腕表.app/空文件";
    let header = zip_header(name, 0, crc32_ieee(b"")).unwrap();
    assert_eq!(u32_at(&header, 14), 0);
    assert_eq!(u32_at(&header, 18), 0);
    assert_eq!(u16_at(&header, 26) as usize, name.len());
    assert_eq!(&header[30..30 + name.len()], name.as_bytes());
    assert!(zip_header("META-INF/", 0, 0).is_ok());
}

#[test]
fn paths_cannot_escape_payload_or_be_silently_renamed() {
    for name in ["", "/absolute", "../file", "Payload/../file", "Payload/./file",
        "Payload//file", "Payload/\\file", "C:/file", "Payload/\0file"] {
        assert!(validate_zip_path(name).is_err(), "{name:?}");
    }
    assert!(validate_zip_path(&"a".repeat(u16::MAX as usize + 1)).is_err());
    assert!(validate_zip_path("Payload/Watch.app/PlugIns/Extension.appex/").is_ok());
    assert_eq!(archive_relative_path(Path::new("_CodeSignature/CodeResources")).unwrap(),
        "_CodeSignature/CodeResources");
    assert!(archive_relative_path(Path::new("../escape")).is_err());
}

#[test]
fn plist_framing_is_big_endian_and_round_trips() {
    let mut input = Dictionary::new();
    insert_string(&mut input, "MediaSubdir", "PublicStaging/Watch.app.ipa");
    insert_integer(&mut input, "InstallTransferredDirectory", 1);
    let frame = encode_plist_frame(input.clone()).unwrap();
    assert_eq!(parse_plist_length(&frame[..4]).unwrap(), frame.len() - 4);
    assert_eq!(u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize, frame.len() - 4);
    assert_eq!(decode_plist_payload(&frame[4..]).unwrap(), input);
}

#[test]
fn malformed_plist_frames_are_rejected_before_allocating_payload() {
    for bytes in [&[][..], &[0, 0, 1][..], &[0, 0, 0, 0][..], &[255, 255, 255, 255][..]] {
        assert!(parse_plist_length(bytes).is_err());
    }
    assert_eq!(parse_plist_length(&(MAX_PLIST_BYTES as u32).to_be_bytes()).unwrap(), MAX_PLIST_BYTES);
    assert!(parse_plist_length(&((MAX_PLIST_BYTES + 1) as u32).to_be_bytes()).is_err());
    assert!(decode_plist_payload(b"not a plist").is_err());
    let mut scalar = Vec::new();
    Value::String("not a dictionary".into()).to_writer_xml(&mut scalar).unwrap();
    assert!(decode_plist_payload(&scalar).is_err());
}

#[test]
fn binary_dictionary_responses_are_supported() {
    let input = progress(24);
    let mut bytes = Vec::new();
    Value::Dictionary(input.clone()).to_writer_binary(&mut bytes).unwrap();
    assert_eq!(decode_plist_payload(&bytes).unwrap(), input);
}

#[test]
fn only_data_complete_reports_final_progress() {
    assert_eq!(parse_install_response(&progress(37)).unwrap(), InstallResponse::Progress(37));
    assert_eq!(parse_install_response(&progress(100)).unwrap(), InstallResponse::Progress(99));
    assert_eq!(parse_install_response(&progress(999)).unwrap(), InstallResponse::Progress(99));
    let mut response = Dictionary::new();
    insert_string(&mut response, "Status", "DataComplete");
    assert_eq!(parse_install_response(&response).unwrap(), InstallResponse::Complete);
    assert!(parse_install_response(&Dictionary::new()).is_err());
}

#[test]
fn errors_override_completion_at_both_protocol_levels() {
    let mut response = failure("invalid signature");
    insert_string(&mut response, "Status", "DataComplete");
    assert!(parse_install_response(&response).is_err());
    let mut response = Dictionary::new();
    insert_string(&mut response, "Status", "DataComplete");
    response.insert("InstallProgressDict".into(), Value::Dictionary(failure("IXErrorDomain Code=48")));
    let error = parse_install_response(&response).unwrap_err();
    assert!(is_watch_coordinator_conflict(&error));
}

#[test]
fn empty_and_zero_error_fields_do_not_fail_normal_progress() {
    let mut response = progress(5);
    insert_string(&mut response, "Error", "");
    assert_eq!(parse_install_response(&response).unwrap(), InstallResponse::Progress(5));
    insert_integer(&mut response, "Error", 0);
    assert_eq!(parse_install_response(&response).unwrap(), InstallResponse::Progress(5));
}
