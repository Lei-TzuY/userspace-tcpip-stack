use toy_tcpip::sflow::{SflowDatagram, SflowError};

fn datagram(sample_count: u32, samples: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&5u32.to_be_bytes()); // version
    data.extend_from_slice(&1u32.to_be_bytes()); // IPv4 agent address type
    data.extend_from_slice(&[192, 0, 2, 1]);
    data.extend_from_slice(&0u32.to_be_bytes()); // sub-agent id
    data.extend_from_slice(&1u32.to_be_bytes()); // sequence
    data.extend_from_slice(&1000u32.to_be_bytes()); // uptime
    data.extend_from_slice(&sample_count.to_be_bytes());
    data.extend_from_slice(samples);
    data
}

fn sample_header(format: u32, declared_len: u32, body: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&format.to_be_bytes());
    data.extend_from_slice(&declared_len.to_be_bytes());
    data.extend_from_slice(body);
    data
}

#[test]
fn zero_sample_datagram_remains_valid() {
    let parsed = SflowDatagram::parse(&datagram(0, &[])).unwrap();
    assert!(parsed.samples.is_empty());
}

#[test]
fn declared_sample_without_header_is_rejected() {
    assert_eq!(
        SflowDatagram::parse(&datagram(1, &[])),
        Err(SflowError::InvalidLength)
    );
}

#[test]
fn truncated_sample_header_is_rejected() {
    assert_eq!(
        SflowDatagram::parse(&datagram(1, &[0, 0, 0, 1])),
        Err(SflowError::InvalidLength)
    );
}

#[test]
fn sample_body_shorter_than_declared_length_is_rejected() {
    let sample = sample_header(99, 8, &[1, 2, 3, 4]);
    assert_eq!(
        SflowDatagram::parse(&datagram(1, &sample)),
        Err(SflowError::InvalidLength)
    );
}

#[test]
fn second_declared_sample_must_also_be_present() {
    let first = sample_header(99, 4, &[1, 2, 3, 4]);
    assert_eq!(
        SflowDatagram::parse(&datagram(2, &first)),
        Err(SflowError::InvalidLength)
    );
}

#[test]
fn well_framed_unknown_sample_format_remains_extensible() {
    let sample = sample_header(99, 4, &[1, 2, 3, 4]);
    let parsed = SflowDatagram::parse(&datagram(1, &sample)).unwrap();
    assert!(parsed.samples.is_empty());
}
