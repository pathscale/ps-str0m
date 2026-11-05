use std::time::SystemTime;

use crate::util::SystemTimeExt;

use super::{FeedbackMessageType, RtcpType, Ssrc};
use super::{RtcpHeader, RtcpPacket};

//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |V=2|P|reserved |   PT=XR=207   |             length            |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                              SSRC                             |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   :                         report blocks                         :
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

/// Extended receiver report (XR).
///
/// RFC 3611: <https://datatracker.ietf.org/doc/html/rfc3611#page-21>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedReport {
    /// The SSRC this report is for.
    pub ssrc: Ssrc,
    /// The blocks reported.
    pub blocks: Vec<ReportBlock>,
}

/// Parts of an extended report XR.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum ReportBlock {
    Rrtr(Rrtr),
    Dlrr(Dlrr),
}

//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |     BT=4      |   reserved    |       block length = 2        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |              NTP timestamp, most significant word              |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |             NTP timestamp, least significant word              |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

/// Receiver Reference Time Report Block.
///
/// <https://datatracker.ietf.org/doc/html/rfc3611#section-4.4>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct Rrtr {
    pub ntp_time: SystemTime,
}

//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |     BT=5      |   reserved    |         block length          |
//   +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
//   |                 SSRC_1 (SSRC of first receiver)                | sub-
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ block
//   |                         last RR (LRR)                         |   1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                   delay since last RR (DLRR)                  |
//   +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
//   |                 SSRC_2 (SSRC of second receiver)              | sub-
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ block
//   :                               ...                             :   2
//   +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

/// DLRR Report Block
///
/// <https://datatracker.ietf.org/doc/html/rfc3611#section-4.5>
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct Dlrr {
    pub items: Vec<DlrrItem>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DlrrItem {
    pub ssrc: Ssrc,
    pub last_rr_time: u32,
    pub last_rr_delay: u32,
}

impl RtcpPacket for ExtendedReport {
    fn header(&self) -> RtcpHeader {
        RtcpHeader {
            rtcp_type: RtcpType::ExtendedReport,
            feedback_message_type: FeedbackMessageType::NotUsed,
            words_less_one: (self.length_words() - 1) as u16,
        }
    }

    fn length_words(&self) -> usize {
        let header = 1;
        let ssrc = 1;
        let blocks: usize = self.blocks.iter().map(|b| b.len() / 4).sum();
        header + ssrc + blocks
    }

    fn write_to(&self, buf: &mut [u8]) -> usize {
        let mut len = self.header().write_to(buf);

        buf[4..8].copy_from_slice(&self.ssrc.to_be_bytes());
        len += 4;

        for block in self.blocks.iter() {
            len += match block {
                ReportBlock::Rrtr(b) => b.write_to(&mut buf[len..]),
                ReportBlock::Dlrr(b) => b.write_to(&mut buf[len..]),
            };
        }

        len
    }
}

impl ReportBlock {
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Rrtr(_) => Rrtr::len(),
            Self::Dlrr(v) => v.len(),
        }
    }
}

impl Rrtr {
    fn write_to(&self, buf: &mut [u8]) -> usize {
        // block type
        buf[0] = 4_u8;
        // reserved;
        buf[1] = 0_u8;
        // block length
        buf[2..4].copy_from_slice(&2_u16.to_be_bytes());

        // NTP timestamp
        let mt = self.ntp_time.as_ntp_64();
        buf[4..12].copy_from_slice(&mt.to_be_bytes());

        12
    }

    fn len() -> usize {
        12
    }
}

impl Dlrr {
    fn write_to(&self, buf: &mut [u8]) -> usize {
        // block type
        buf[0] = 5_u8;
        // reserved;
        buf[1] = 0_u8;
        // block length, in 32-bit words (RFC 3611 §3): each DLRR sub-block is 3 words
        // (ssrc + last_rr + delay = 12 bytes). Must match the parser, which divides this
        // field by 3 to recover the item count.
        let len: u16 = self.items.len() as u16 * 3_u16;
        buf[2..4].copy_from_slice(&len.to_be_bytes());

        let mut buf = &mut buf[4..];

        for item in self.items.iter() {
            buf[0..4].copy_from_slice(&item.ssrc.to_be_bytes());
            buf[4..8].copy_from_slice(&item.last_rr_time.to_be_bytes());
            buf[8..12].copy_from_slice(&item.last_rr_delay.to_be_bytes());
            // advance past the full 12-byte sub-block
            buf = &mut buf[12..];
        }

        self.len()
    }

    fn len(&self) -> usize {
        4 + (self.items.len() * 4 * 3)
    }
}

impl<'a> TryFrom<&'a [u8]> for ExtendedReport {
    type Error = &'static str;

    fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
        if buf.len() < 4 {
            return Err("Less than 4 bytes for ExtendedReport");
        }

        let ssrc = u32::from_be_bytes(buf[..4].try_into().unwrap()).into();

        let mut blocks: Vec<ReportBlock> = Vec::new();
        let mut buf = &buf[4..];

        while let Ok(block) = buf.try_into() {
            let block: ReportBlock = block;
            let len = block.len();
            blocks.push(block);
            // A block's reported len may exceed the remaining bytes for a
            // truncated/malformed packet. Guard against slicing past the end
            // (panic) and against a zero len that would spin forever.
            if len == 0 || len >= buf.len() {
                break;
            }
            buf = &buf[len..];
        }

        Ok(ExtendedReport { ssrc, blocks })
    }
}

impl<'a> TryFrom<&'a [u8]> for ReportBlock {
    type Error = &'static str;

    fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
        if buf.is_empty() {
            return Err("not enough data");
        }

        let block_type: u8 = buf[0];
        match block_type {
            4 => {
                let block = Rrtr::try_from(buf)?;
                Ok(Self::Rrtr(block))
            }
            5 => {
                let block = Dlrr::try_from(buf)?;
                Ok(Self::Dlrr(block))
            }
            _ => Err("unknown block type"),
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for Rrtr {
    type Error = &'static str;

    fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
        if buf.len() < 12 {
            return Err("Less than 12 bytes for Rrtr");
        }

        let ntp_time = u64::from_be_bytes(buf[4..4 + 8].try_into().unwrap());
        let ntp_time = SystemTime::from_ntp_64(ntp_time);

        Ok(Rrtr { ntp_time })
    }
}

impl<'a> TryFrom<&'a [u8]> for Dlrr {
    type Error = &'static str;

    fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
        if buf.len() < 4 {
            return Err("Less than 4 bytes for Dlrr");
        }

        let length_words = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
        if length_words % 3 != 0 {
            return Err("DLRR length is not a whole number of sub-blocks");
        }
        let payload_len = length_words
            .checked_mul(4)
            .ok_or("DLRR length overflows address space")?;
        let end = 4usize
            .checked_add(payload_len)
            .ok_or("DLRR length overflows address space")?;
        if end > buf.len() {
            return Err("Truncated DLRR sub-block");
        }

        let blocks = length_words / 3;
        let mut items: Vec<DlrrItem> = Vec::with_capacity(blocks);
        for item in buf[4..end].chunks_exact(12) {
            let ssrc = u32::from_be_bytes([item[0], item[1], item[2], item[3]]).into();
            let last_rr_time = u32::from_be_bytes([item[4], item[5], item[6], item[7]]);
            let last_rr_delay = u32::from_be_bytes([item[8], item[9], item[10], item[11]]);
            items.push(DlrrItem {
                ssrc,
                last_rr_time,
                last_rr_delay,
            });
        }

        Ok(Dlrr { items })
    }
}
