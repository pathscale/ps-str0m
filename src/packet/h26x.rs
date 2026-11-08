use super::PacketError;

// 4,096 RTP payloads of 1,200 bytes are about 4.7 MiB. This leaves room
// for NAL framing and larger negotiated MTUs without using the queue's packet
// count as a byte bound. Applications can size the limit for their stream.
pub(crate) const DEFAULT_REASSEMBLY_LIMIT: usize = 8 * 1024 * 1024;

const START_CODE: [u8; 4] = [0, 0, 0, 1];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Reassembly<const N: usize> {
    limit: usize,
    pending: Option<([u8; N], Vec<u8>)>,
}

impl<const N: usize> Default for Reassembly<N> {
    fn default() -> Self {
        Self {
            limit: DEFAULT_REASSEMBLY_LIMIT,
            pending: None,
        }
    }
}

impl<const N: usize> Reassembly<N> {
    pub(super) fn set_limit(&mut self, limit: usize) {
        self.reset();
        self.limit = limit;
    }

    pub(super) fn limit(&self) -> usize {
        self.limit
    }

    pub(super) fn reset(&mut self) {
        self.pending = None;
    }

    pub(super) fn finish(&mut self) -> Result<(), PacketError> {
        if self.pending.take().is_some() {
            Err(PacketError::ErrH26xFragmentSequence)
        } else {
            Ok(())
        }
    }

    pub(super) fn size_hint(&self, packets_size: usize) -> usize {
        let estimated_packets = (packets_size / 1200).saturating_add(1);
        packets_size
            .saturating_add(4usize.saturating_mul(estimated_packets))
            .min(self.limit)
    }

    pub(super) fn reserve(&self, out: &mut Vec<u8>, extra: usize) -> Result<(), PacketError> {
        reserve_bounded(out, extra, self.limit, self.limit)
    }

    pub(super) fn fragment(
        &mut self,
        (start, end): (bool, bool),
        header: [u8; N],
        payload: &[u8],
        out: &mut Vec<u8>,
        avc: bool,
    ) -> Result<bool, PacketError> {
        if start && end {
            return Err(PacketError::ErrH26xFragmentSequence);
        }

        let (first_header, mut pending) = if start {
            self.reset();
            (header, Vec::new())
        } else {
            self.pending
                .take()
                .ok_or(PacketError::ErrH26xFragmentSequence)?
        };
        if first_header != header {
            return Err(PacketError::ErrH26xFragmentSequence);
        }

        // Count output already produced for this access unit, plus the
        // reconstructed NAL header and its framing, even before the end FU.
        let err = PacketError::ErrH26xReassemblyLimit { limit: self.limit };
        let payload_limit = self
            .limit
            .checked_sub(out.len())
            .and_then(|left| left.checked_sub(START_CODE.len() + N))
            .ok_or(err)?;
        let payload_len = checked_add(pending.len(), payload.len(), self.limit)?;
        if payload_len > payload_limit {
            return Err(PacketError::ErrH26xReassemblyLimit { limit: self.limit });
        }
        let nalu_len = N + payload_len;
        let prefix = nalu_prefix(nalu_len, avc, self.limit)?;
        if end {
            // The last payload is borrowed directly. Taking the accumulator
            // above also frees it on any error and after a successful end.
            self.reserve(out, START_CODE.len() + nalu_len)?;
            out.extend_from_slice(&prefix);
            out.extend_from_slice(&first_header);
            out.extend_from_slice(&pending);
            out.extend_from_slice(payload);
        } else {
            reserve_bounded(&mut pending, payload.len(), payload_limit, self.limit)?;
            pending.extend_from_slice(payload);
            self.pending = Some((first_header, pending));
        }
        Ok(end)
    }
}

pub(super) fn checked_add(a: usize, b: usize, limit: usize) -> Result<usize, PacketError> {
    a.checked_add(b)
        .filter(|&sum| sum <= limit)
        .ok_or(PacketError::ErrH26xReassemblyLimit { limit })
}

pub(super) fn nalu_prefix(len: usize, avc: bool, limit: usize) -> Result<[u8; 4], PacketError> {
    if avc {
        let len = u32::try_from(len).map_err(|_| PacketError::ErrH26xReassemblyLimit { limit })?;
        Ok(len.to_be_bytes())
    } else {
        Ok(START_CODE)
    }
}

pub(super) fn reserve_bounded(
    buf: &mut Vec<u8>,
    additional: usize,
    maximum: usize,
    reported_limit: usize,
) -> Result<(), PacketError> {
    let needed = checked_add(buf.len(), additional, maximum)
        .map_err(|_| PacketError::ErrH26xReassemblyLimit {
            limit: reported_limit,
        })?;
    if needed > buf.capacity() {
        // Preserve amortized growth without Vec::reserve's unconstrained
        // doubling above the configured maximum.
        let target = needed
            .max(buf.capacity().saturating_mul(2).min(maximum))
            .min(isize::MAX as usize);
        if target < needed {
            return Err(PacketError::ErrH26xReassemblyLimit {
                limit: reported_limit,
            });
        }
        buf.try_reserve_exact(target - buf.len())
            .map_err(|_| PacketError::ErrH26xReassemblyAllocation)?;
    }
    Ok(())
}

/// Reads length-prefixed NALs without allocating. The optional skipped bytes
/// are DONL before the first NAL and DOND before later NALs.
#[derive(Clone)]
pub(super) struct Aggregation<'a> {
    remaining: &'a [u8],
    skip: usize,
    next_skip: usize,
    stap_a: bool,
}

impl<'a> Aggregation<'a> {
    pub(super) fn new(remaining: &'a [u8], first_skip: usize, next_skip: usize) -> Self {
        Self {
            remaining,
            skip: first_skip,
            next_skip,
            stap_a: false,
        }
    }

    pub(super) fn stap_a(remaining: &'a [u8]) -> Self {
        Self {
            stap_a: true,
            ..Self::new(remaining, 0, 0)
        }
    }

    pub(super) fn next_nalu(&mut self) -> Result<Option<&'a [u8]>, PacketError> {
        // The H264 depacketizer accepts a trailing zero byte on STAP-A.
        if self.remaining.is_empty() || (self.stap_a && self.remaining == [0]) {
            return Ok(None);
        }
        let data = self
            .remaining
            .get(self.skip..)
            .ok_or(PacketError::ErrShortPacket)?;
        let [hi, lo, rest @ ..] = data else {
            return Err(PacketError::ErrShortPacket);
        };
        let len = usize::from(u16::from_be_bytes([*hi, *lo]));
        let nalu = rest.get(..len).ok_or_else(|| {
            if self.stap_a {
                PacketError::StapASizeLargerThanBuffer(len, rest.len())
            } else {
                PacketError::ErrShortPacket
            }
        })?;
        self.remaining = &rest[len..];
        self.skip = self.next_skip;
        Ok(Some(nalu))
    }
}

pub(super) fn aggregation_size(
    mut units: Aggregation<'_>,
    min_units: usize,
    limit: usize,
    mut validate: impl FnMut(&[u8]) -> Result<(), PacketError>,
) -> Result<usize, PacketError> {
    let mut count = 0;
    let mut total = 0;
    while let Some(nalu) = units.next_nalu()? {
        validate(nalu)?;
        total = checked_add(total, START_CODE.len(), limit)?;
        total = checked_add(total, nalu.len(), limit)?;
        count += 1;
    }
    if count < min_units {
        return Err(PacketError::ErrShortPacket);
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::PacketError;
    use crate::format::Codec;
    use crate::packet::{CodecDepacketizer, CodecExtra, Depacketizer};

    struct Wire {
        codec: Codec,
        start: &'static [u8],
        middle: &'static [u8],
        end: &'static [u8],
        mismatched_end: &'static [u8],
        start_and_end: &'static [u8],
        single: &'static [u8],
        nalu_header: &'static [u8],
        aggregate: &'static [u8],
    }

    const WIRE: [Wire; 3] = [
        Wire {
            codec: Codec::H264,
            start: &[0x7c, 0x85, 0x11],
            middle: &[0x7c, 5, 0x22],
            end: &[0x7c, 0x45, 0x33],
            mismatched_end: &[0x5c, 0x45, 0x33],
            start_and_end: &[0x7c, 0xc5, 0x33],
            single: &[0x61, 0xaa],
            nalu_header: &[0x65],
            aggregate: &[0x78, 0, 2, 0x65, 0xab, 0, 2, 0x61, 0xbc],
        },
        Wire {
            codec: Codec::H265,
            start: &[0x62, 0x19, 0x93, 0x11],
            middle: &[0x62, 0x19, 19, 0x22],
            end: &[0x62, 0x19, 0x53, 0x33],
            mismatched_end: &[0x62, 0x11, 0x53, 0x33],
            start_and_end: &[0x62, 0x19, 0xd3, 0x33],
            single: &[2, 1, 0xaa],
            nalu_header: &[0x26, 0x19],
            aggregate: &[0x60, 1, 0, 3, 0x26, 1, 0xab, 0, 3, 2, 1, 0xbc],
        },
        Wire {
            codec: Codec::H266,
            start: &[3, 0xe9, 0x87, 0x11],
            middle: &[3, 0xe9, 7, 0x22],
            end: &[3, 0xe9, 0x47, 0x33],
            mismatched_end: &[3, 0xea, 0x47, 0x33],
            start_and_end: &[3, 0xe9, 0xc7, 0x33],
            single: &[0, 1, 0xaa],
            nalu_header: &[3, 0x39],
            aggregate: &[0, 0xe1, 0, 3, 0, 0x39, 0xab, 0, 3, 0, 1, 0xbc],
        },
    ];

    fn is_keyframe(extra: CodecExtra) -> bool {
        match extra {
            CodecExtra::H264(e) => e.is_keyframe,
            CodecExtra::H265(e) => e.is_keyframe,
            CodecExtra::H266(e) => e.is_keyframe,
            _ => false,
        }
    }

    #[test]
    fn fragment_budget_counts_existing_output_headers_and_prefix() -> Result<(), PacketError> {
        for wire in &WIRE {
            let prefix: &[u8] = &[0, 0, 0, 1];
            let expected = [
                prefix,
                wire.single,
                prefix,
                wire.nalu_header,
                &[0x11, 0x22, 0x33],
            ]
            .concat();

            for limit in [expected.len(), expected.len() - 1] {
                let mut depack = CodecDepacketizer::from(wire.codec);
                depack.set_h26x_reassembly_limit(limit);
                let mut out = Vec::new();
                let mut extra = CodecExtra::None;
                depack.depacketize(wire.single, &mut out, &mut extra)?;
                let original = out.clone();
                let original_extra = extra;
                depack.depacketize(wire.start, &mut out, &mut extra)?;
                depack.depacketize(wire.middle, &mut out, &mut extra)?;
                assert_eq!(out, original);
                assert_eq!(extra, original_extra);
                let result = depack.depacketize(wire.end, &mut out, &mut extra);
                if limit == expected.len() {
                    result?;
                    assert_eq!(out, expected);
                    assert!(is_keyframe(extra));
                } else {
                    assert_eq!(result, Err(PacketError::ErrH26xReassemblyLimit { limit }));
                    assert_eq!(out, original);
                    assert_eq!(extra, original_extra);
                }
                assert_eq!(
                    depack.depacketize(wire.end, &mut out, &mut extra),
                    Err(PacketError::ErrH26xFragmentSequence)
                );
                out.clear();
                extra = CodecExtra::None;
                depack.depacketize(wire.single, &mut out, &mut extra)?;
                assert_eq!(out, original);
                assert!(!is_keyframe(extra));
            }

            // Force rejection on a middle fragment, without ever providing an end.
            let mut depack = CodecDepacketizer::from(wire.codec);
            let limit = 4 + wire.nalu_header.len() + 1;
            depack.set_h26x_reassembly_limit(limit);
            let mut out = Vec::new();
            let mut extra = CodecExtra::None;
            depack.depacketize(wire.start, &mut out, &mut extra)?;
            assert_eq!(
                depack.depacketize(wire.middle, &mut out, &mut extra),
                Err(PacketError::ErrH26xReassemblyLimit { limit })
            );
            assert_eq!(
                depack.depacketize(wire.end, &mut out, &mut extra),
                Err(PacketError::ErrH26xFragmentSequence)
            );
            assert!(out.is_empty());
            assert_eq!(extra, CodecExtra::None);
        }
        Ok(())
    }

    #[test]
    fn malformed_or_interrupted_fragments_cannot_leak_into_later_nals() -> Result<(), PacketError> {
        for wire in &WIRE {
            let mut depack = CodecDepacketizer::from(wire.codec);
            let mut out = Vec::new();
            let mut extra = CodecExtra::None;
            for (bad, error) in [
                (wire.mismatched_end, PacketError::ErrH26xFragmentSequence),
                (wire.start_and_end, PacketError::ErrH26xFragmentSequence),
                (&wire.start[..1], PacketError::ErrShortPacket),
            ] {
                depack.depacketize(wire.start, &mut out, &mut extra)?;
                assert_eq!(depack.depacketize(bad, &mut out, &mut extra), Err(error));
                assert_eq!(
                    depack.depacketize(wire.end, &mut out, &mut extra),
                    Err(PacketError::ErrH26xFragmentSequence)
                );
                assert!(out.is_empty());
                assert_eq!(extra, CodecExtra::None);
            }

            depack.depacketize(wire.start, &mut out, &mut extra)?;
            depack.depacketize(wire.single, &mut out, &mut extra)?;
            assert_eq!(
                depack.depacketize(wire.end, &mut out, &mut extra),
                Err(PacketError::ErrH26xFragmentSequence)
            );
            assert_eq!(out, [&[0, 0, 0, 1][..], wire.single].concat());
            assert!(!is_keyframe(extra));

            out.clear();
            extra = CodecExtra::None;
            depack.depacketize(wire.start, &mut out, &mut extra)?;
            let mut restart = wire.start.to_vec();
            *restart.last_mut().unwrap() = 0xde;
            depack.depacketize(&restart, &mut out, &mut extra)?;
            depack.depacketize(wire.end, &mut out, &mut extra)?;
            assert_eq!(
                out,
                [&[0, 0, 0, 1][..], wire.nalu_header, &[0xde, 0x33]].concat()
            );
            assert!(is_keyframe(extra));
        }
        Ok(())
    }

    #[test]
    fn malformed_aggregate_keeps_existing_output_and_keyframe_metadata() -> Result<(), PacketError> {
        for wire in &WIRE {
            let mut depack = CodecDepacketizer::from(wire.codec);
            let mut out = Vec::new();
            let mut extra = CodecExtra::None;
            depack.depacketize(wire.single, &mut out, &mut extra)?;
            let before = out.clone();
            let before_extra = extra;
            let mut malformed = wire.aggregate.to_vec();
            malformed.push(1); // Two valid NALs followed by a truncated length.
            assert_eq!(
                depack.depacketize(&malformed, &mut out, &mut extra),
                Err(PacketError::ErrShortPacket)
            );
            assert_eq!(out, before);
            assert_eq!(extra, before_extra);

            let framed_size = 2 * (4 + wire.single.len());
            let limit = before.len() + framed_size - 1;
            depack.set_h26x_reassembly_limit(limit);
            assert_eq!(
                depack.depacketize(wire.aggregate, &mut out, &mut extra),
                Err(PacketError::ErrH26xReassemblyLimit { limit })
            );
            assert_eq!(out, before);
            assert_eq!(extra, before_extra);

            depack.set_h26x_reassembly_limit(limit + 1);
            depack.depacketize(wire.aggregate, &mut out, &mut extra)?;
            assert_eq!(out.len(), limit + 1);
            assert_eq!(out[before.len() + 4 + wire.single.len() - 1], 0xab);
            assert_eq!(out.last(), Some(&0xbc));
            assert!(is_keyframe(extra));
        }
        Ok(())
    }

    #[test]
    fn default_recovers_byte_exact_nal_larger_than_128_kib() -> Result<(), PacketError> {
        for wire in &WIRE {
            let mut depack = CodecDepacketizer::from(wire.codec);
            let mut out = Vec::new();
            let mut extra = CodecExtra::None;
            assert_eq!(
                depack.depacketize(wire.end, &mut out, &mut extra),
                Err(PacketError::ErrH26xFragmentSequence)
            );
            depack.depacketize(wire.start, &mut out, &mut extra)?;
            let mut expected = [&[0, 0, 0, 1][..], wire.nalu_header, &[0x11]].concat();
            let header = &wire.middle[..wire.middle.len() - 1];
            let mut packet = header.to_vec();
            for value in 0..129_u8 {
                packet.resize(header.len() + 1024, value);
                depack.depacketize(&packet, &mut out, &mut extra)?;
                expected.extend_from_slice(&packet[header.len()..]);
                packet.truncate(header.len());
            }
            assert!(out.is_empty());
            assert_eq!(extra, CodecExtra::None);
            depack.depacketize(wire.end, &mut out, &mut extra)?;
            expected.push(0x33);
            assert!(expected.len() > 128 * 1024);
            assert_eq!(out, expected);
            assert!(is_keyframe(extra));
        }
        Ok(())
    }

    #[test]
    fn h264_avc_allows_empty_fragments_at_exact_limit() -> Result<(), PacketError> {
        let mut depack = crate::packet::H264Depacketizer::default();
        depack.is_avc = true;
        depack.set_reassembly_limit(6);
        let mut out = Vec::new();
        let mut extra = CodecExtra::None;
        depack.depacketize(&[0x7c, 0x85], &mut out, &mut extra)?;
        depack.depacketize(&[0x7c, 5, 0x11], &mut out, &mut extra)?;
        depack.depacketize(&[0x7c, 0x45], &mut out, &mut extra)?;
        assert_eq!(out, [0, 0, 0, 2, 0x65, 0x11]);
        assert!(is_keyframe(extra));
        Ok(())
    }
}
