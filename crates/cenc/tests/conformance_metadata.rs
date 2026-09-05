//! Public-API metadata witnesses. Synthetic fragment writers are independent of
//! the production parser. The checked-in init supplies a real sample entry;
//! no production parser is used to calculate expected sample locations.
//! Unsupported capability tests record rejection, never positive ISO coverage.
mod common;
use iori_cenc::{CencError, ParsedCenc};

fn boxed(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut data = ((payload.len() + 8) as u32).to_be_bytes().to_vec();
    data.extend_from_slice(kind);
    data.extend_from_slice(payload);
    data
}
fn init() -> Vec<u8> {
    let fixture = include_bytes!("fixtures/fmp4/cbcs.mp4");
    let end = common::find_top_level_box(fixture, b"moof").unwrap().start;
    let mut init = fixture[..end].to_vec();
    let trex = init.windows(4).position(|v| v == b"trex").unwrap();
    init[trex + 20..trex + 24].copy_from_slice(&16u32.to_be_bytes());
    init
}
fn media(samples: u32, extra: &[u8]) -> Vec<u8> {
    let mut data = boxed(b"mdat", &vec![0x35; samples as usize * 16]);
    let mut tfhd = 1u32.to_be_bytes().to_vec();
    tfhd.extend_from_slice(&1u32.to_be_bytes());
    tfhd.extend_from_slice(&8u64.to_be_bytes());
    let mut traf = boxed(b"tfhd", &tfhd);
    let mut trun = vec![0; 4];
    trun.extend_from_slice(&samples.to_be_bytes());
    traf.extend(boxed(b"trun", &trun));
    traf.extend_from_slice(extra);
    let mut moof = boxed(b"mfhd", &[0, 0, 0, 0, 0, 0, 0, 1]);
    moof.extend(boxed(b"traf", &traf));
    data.extend(boxed(b"moof", &moof));
    data
}
fn senc() -> Vec<u8> {
    let mut payload = vec![0, 0, 0, 2];
    payload.extend_from_slice(&1u32.to_be_bytes());
    payload.extend_from_slice(&1u16.to_be_bytes());
    payload.extend_from_slice(&0u16.to_be_bytes());
    payload.extend_from_slice(&16u32.to_be_bytes());
    payload
}
fn entry(protected: bool, iv_size: usize, kid: u8) -> Vec<u8> {
    let mut data = vec![0, 0x19, u8::from(protected), 0];
    data.extend_from_slice(&[kid; 16]);
    if protected {
        data.push(iv_size as u8);
        data.extend(vec![kid + 1; iv_size]);
    }
    data
}
fn sgpd(version: u8, variable: bool, default: u32, entries: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = vec![version, 0, 0, 0];
    payload.extend_from_slice(b"seig");
    if version >= 1 {
        payload
            .extend_from_slice(&(if variable { 0 } else { entries[0].len() as u32 }).to_be_bytes());
    }
    if version >= 2 {
        payload.extend_from_slice(&default.to_be_bytes());
    }
    payload.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for entry in entries {
        if version >= 1 && variable {
            payload.extend_from_slice(&(entry.len() as u32).to_be_bytes());
        }
        payload.extend_from_slice(entry);
    }
    boxed(b"sgpd", &payload)
}
fn sbgp(version: u8, runs: &[(u32, u32)]) -> Vec<u8> {
    let mut payload = vec![version, 0, 0, 0];
    payload.extend_from_slice(b"seig");
    if version == 1 {
        payload.extend_from_slice(&0u32.to_be_bytes());
    }
    payload.extend_from_slice(&(runs.len() as u32).to_be_bytes());
    for (count, index) in runs {
        payload.extend_from_slice(&count.to_be_bytes());
        payload.extend_from_slice(&index.to_be_bytes());
    }
    boxed(b"sbgp", &payload)
}

#[test]
fn senc_versions_one_two_and_unknown_are_explicit_capability_rejections() {
    let init = init();
    // Header witnesses only: these establish version dispatch, not complete
    // multi-key version-1/2 record validation or implementation support.
    for version in [1, 2, 3, 255] {
        let mut payload = senc();
        payload[0] = version;
        let error =
            ParsedCenc::parse_with_init(&media(1, &boxed(b"senc", &payload)), &init).unwrap_err();
        assert!(
            matches!(error, CencError::InvalidSenc(message) if message == format!("unsupported senc version {version}"))
        );
    }
}

#[test]
fn sve1_and_unknown_scheme_have_distinct_public_api_errors() {
    let media = media(1, &[]);
    for scheme in [*b"sve1", *b"zzzz"] {
        let mut init = init();
        let schm = init.windows(4).position(|v| v == b"schm").unwrap();
        init[schm + 8..schm + 12].copy_from_slice(&scheme);
        let error = ParsedCenc::parse_with_init(&media, &init).unwrap_err();
        match scheme {
            [b's', b'v', b'e', b'1'] => assert!(
                matches!(error, CencError::UnsupportedContentSensitiveScheme(s) if s == "sve1")
            ),
            _ => assert!(matches!(error, CencError::UnsupportedScheme(s) if s == "zzzz")),
        }
    }
}

#[test]
fn senc_each_reserved_flag_bit_is_rejected() {
    let init = init();
    for bit in 2..24 {
        let mut payload = senc();
        payload[..4].copy_from_slice(&(2u32 | (1 << bit)).to_be_bytes());
        let error =
            ParsedCenc::parse_with_init(&media(1, &boxed(b"senc", &payload)), &init).unwrap_err();
        assert!(
            matches!(error, CencError::InvalidSenc(message) if message.contains("unsupported senc flags")),
            "bit={bit}"
        );
    }
}

#[test]
fn senc_every_record_truncation_is_rejected_without_panic() {
    let init = init();
    let complete = senc();
    assert_eq!(
        ParsedCenc::parse_with_init(&media(1, &boxed(b"senc", &complete)), &init)
            .unwrap()
            .jobs
            .len(),
        1
    );
    for cut in 0..complete.len() {
        let truncated = media(1, &boxed(b"senc", &complete[..cut]));
        let result = std::panic::catch_unwind(|| ParsedCenc::parse_with_init(&truncated, &init));
        assert!(result.is_ok(), "panic at senc payload length {cut}");
        assert!(
            result.unwrap().is_err(),
            "accepted senc payload length {cut}"
        );
    }
}

#[test]
fn senc_count_disagreement_is_rejected_before_record_allocation() {
    let init = init();
    for count in [0, 2, 4096, u32::MAX] {
        let mut payload = senc();
        payload[4..8].copy_from_slice(&count.to_be_bytes());
        let error =
            ParsedCenc::parse_with_init(&media(1, &boxed(b"senc", &payload)), &init).unwrap_err();
        assert!(
            matches!(error, CencError::SampleCountMismatch { .. }),
            "count={count}: {error}"
        );
    }
}

#[test]
fn tenc_protected_iv_width_domain_rejects_all_other_byte_values() {
    let base = init();
    let tenc = base.windows(4).position(|v| v == b"tenc").unwrap();
    for width in 0..=255u8 {
        if [0, 8, 16].contains(&width) {
            continue;
        }
        let mut init = base.clone();
        init[tenc + 11] = width;
        let error = ParsedCenc::parse_with_init(&media(1, &[]), &init).unwrap_err();
        assert!(
            matches!(error,CencError::InvalidTenc(message) if message.contains("iv_size")),
            "width={width}"
        );
    }
}

#[test]
fn tenc_constant_iv_width_rejects_zero_and_non_aes_sizes() {
    let base = init();
    let tenc = base.windows(4).position(|v| v == b"tenc").unwrap();
    for width in [0, 1, 7, 9, 15, 17, 255] {
        let mut init = base.clone();
        init[tenc + 28] = width;
        let error = ParsedCenc::parse_with_init(&media(1, &[]), &init).unwrap_err();
        assert!(
            matches!(error,CencError::InvalidTenc(message) if message.contains("constant iv size")),
            "width={width}"
        );
    }
}

#[test]
fn sgpd_fixed_variable_lengths_and_sbgp_versions_have_identical_effective_jobs() {
    let init = init();
    for iv_size in [8, 16] {
        for version in [0, 1, 2] {
            for variable in [false, true] {
                for sbgp_version in [0, 1] {
                    let mut extra = sgpd(version, variable, 0, &[entry(true, iv_size, 9)]);
                    extra.extend(sbgp(sbgp_version, &[(1, 0x10001)]));
                    let parsed = ParsedCenc::parse_with_init(&media(1, &extra), &init).unwrap();
                    assert_eq!(parsed.jobs.len(), 1);
                    let job = &parsed.jobs[0];
                    assert_eq!((job.offset, job.size), (8, 16));
                    assert_eq!(job.kid, [9; 16]);
                    let mut expected_iv = [0; 16];
                    expected_iv[..iv_size].fill(10);
                    assert_eq!(job.iv, expected_iv);
                    assert_eq!(job.pattern.unwrap().crypt_byte_block, 1);
                    assert_eq!(job.pattern.unwrap().skip_byte_block, 9);
                }
            }
        }
    }
}

#[test]
fn group_clear_protected_transitions_and_repeated_kid_preserve_sample_indexes() {
    let mut init = init();
    let tenc = init.windows(4).position(|v| v == b"tenc").unwrap();
    init[tenc + 10] = 0;
    let descriptions = [entry(false, 0, 8), entry(true, 16, 9), entry(true, 8, 10)];
    for sbgp_version in [0, 1] {
        let mut extra = sgpd(1, true, 0, &descriptions);
        extra.extend(sbgp(
            sbgp_version,
            &[
                (1, 0x10001),
                (1, 0x10002),
                (0, 0x10003),
                (1, 0x10003),
                (1, 0x10002),
                (1, 0x10001),
            ],
        ));
        let parsed = ParsedCenc::parse_with_init(&media(5, &extra), &init).unwrap();
        assert_eq!(
            parsed
                .jobs
                .iter()
                .map(|job| (job.offset, job.kid[0]))
                .collect::<Vec<_>>(),
            [(24, 9), (40, 10), (56, 9)]
        );
    }
}

#[test]
fn sgpd_default_matches_explicit_assignment_without_sbgp() {
    let init = init();
    let default = sgpd(2, true, 1, &[entry(true, 16, 9)]);
    let mut explicit = sgpd(1, false, 0, &[entry(true, 16, 9)]);
    explicit.extend(sbgp(0, &[(3, 0x10001)]));
    let a = ParsedCenc::parse_with_init(&media(3, &default), &init).unwrap();
    let b = ParsedCenc::parse_with_init(&media(3, &explicit), &init).unwrap();
    assert_eq!(a.jobs.len(), 3);
    for (a, b) in a.jobs.iter().zip(b.jobs) {
        assert_eq!(
            (a.offset, a.size, a.iv, a.kid, a.pattern),
            (b.offset, b.size, b.iv, b.kid, b.pattern)
        );
    }
}

#[test]
fn invalid_group_namespace_indexes_and_oversized_runs_are_rejected() {
    let init = init();
    for runs in [
        vec![(1, 1)],
        vec![(1, 0x10000)],
        vec![(1, 0x10002)],
        vec![(1, u32::MAX)],
        vec![(2, 0x10001)],
    ] {
        let mut extra = sgpd(1, false, 0, &[entry(true, 16, 9)]);
        extra.extend(sbgp(0, &runs));
        let error = ParsedCenc::parse_with_init(&media(1, &extra), &init).unwrap_err();
        assert!(
            matches!(error, CencError::InvalidSenc(_)),
            "runs={runs:?}: {error}"
        );
    }
}

#[test]
fn sgpd_every_description_truncation_is_rejected_without_panic() {
    let init = init();
    let complete = entry(true, 16, 9);
    for cut in 0..complete.len() {
        let mut extra = sgpd(1, true, 0, &[complete[..cut].to_vec()]);
        extra.extend(sbgp(0, &[(1, 0x10001)]));
        let data = media(1, &extra);
        let result = std::panic::catch_unwind(|| ParsedCenc::parse_with_init(&data, &init));
        assert!(result.is_ok(), "panic at seig length={cut}");
        assert!(result.unwrap().is_err(), "accepted seig length={cut}");
    }
}

#[test]
fn truncated_top_level_box_headers_are_bounded_and_rejected() {
    let init = init();
    for header in [
        vec![0, 0, 0, 16, b'm', b'd', b'a', b't'],
        vec![0, 0, 0, 1, b'm', b'd', b'a', b't', 0, 0, 0, 0, 0, 0, 0, 32],
    ] {
        for cut in 1..=header.len() {
            let result =
                std::panic::catch_unwind(|| ParsedCenc::parse_with_init(&header[..cut], &init));
            assert!(result.is_ok(), "panic at header length={cut}");
            assert!(
                result.unwrap().is_err(),
                "accepted truncated header length={cut}"
            );
        }
    }
}

#[test]
fn senc_and_external_auxiliary_records_produce_identical_sample_jobs() {
    let init = init();
    let mut record = 1u16.to_be_bytes().to_vec();
    record.extend_from_slice(&3u16.to_be_bytes());
    record.extend_from_slice(&13u32.to_be_bytes());
    let mut senc = vec![0, 0, 0, 2, 0, 0, 0, 1];
    senc.extend_from_slice(&record);
    let inline = ParsedCenc::parse_with_init(&media(1, &boxed(b"senc", &senc)), &init).unwrap();
    for version in [0, 1] {
        let mut saiz = vec![0, 0, 0, 0, 8];
        saiz.extend_from_slice(&1u32.to_be_bytes());
        let mut saio = vec![version, 0, 0, 0, 0, 0, 0, 1];
        saio.extend(vec![0; if version == 0 { 4 } else { 8 }]);
        let extra = [boxed(b"saiz", &saiz), boxed(b"saio", &saio)].concat();
        let mut external = media(1, &extra);
        // tfhd declares base 8. The final free payload starts at old_len+8,
        // so the auxiliary relative address is old_len, independent of moof.
        let relative = external.len() as u64;
        let saio = external.windows(4).position(|v| v == b"saio").unwrap();
        if version == 0 {
            external[saio + 12..saio + 16].copy_from_slice(&(relative as u32).to_be_bytes());
        } else {
            external[saio + 12..saio + 20].copy_from_slice(&relative.to_be_bytes());
        }
        external.extend(boxed(b"free", &record));
        let parsed = ParsedCenc::parse_with_init(&external, &init).unwrap();
        assert_eq!(parsed.jobs.len(), 1);
        let a = &parsed.jobs[0];
        let b = &inline.jobs[0];
        assert_eq!(
            (a.offset, a.size, a.iv, a.kid, a.pattern),
            (b.offset, b.size, b.iv, b.kid, b.pattern)
        );
        assert_eq!(a.subsamples, b.subsamples);
        assert_eq!(
            (a.subsamples[0].clear_bytes, a.subsamples[0].encrypted_bytes),
            (3, 13)
        );
    }
}

#[test]
fn huge_group_and_auxiliary_counts_fail_before_untrusted_allocation() {
    let init = init();
    for count in [4096, u32::MAX] {
        let mut sgpd = vec![1, 0, 0, 0, b's', b'e', b'i', b'g', 0, 0, 0, 20];
        sgpd.extend_from_slice(&count.to_be_bytes());
        let mut sbgp = vec![0, 0, 0, 0, b's', b'e', b'i', b'g'];
        sbgp.extend_from_slice(&count.to_be_bytes());
        let mut saio = vec![0, 0, 0, 0];
        saio.extend_from_slice(&count.to_be_bytes());
        let mut saiz_default = vec![0, 0, 0, 0, 8];
        saiz_default.extend_from_slice(&count.to_be_bytes());
        let mut saiz_explicit = vec![0, 0, 0, 0, 0];
        saiz_explicit.extend_from_slice(&count.to_be_bytes());
        for (kind, payload) in [
            (*b"sgpd", sgpd),
            (*b"sbgp", sbgp),
            (*b"saio", saio),
            (*b"saiz", saiz_default),
            (*b"saiz", saiz_explicit),
        ] {
            let data = media(1, &boxed(&kind, &payload));
            let result = std::panic::catch_unwind(|| ParsedCenc::parse_with_init(&data, &init));
            assert!(result.is_ok(), "panic for {kind:?} count={count}");
            assert!(result.unwrap().is_err(), "accepted {kind:?} count={count}");
        }
    }
}
