//! Fixed E8 controller-to-consoled quiescence frame.

pub const FRAME_BYTES: usize = 96;
const MAGIC: [u8; 4] = *b"WRC8";
const MAJOR: u16 = 1;
const MINOR: u16 = 0;
const TYPE_REQUEST: u32 = 1;
const TYPE_ACK: u32 = 2;
const TYPE_READY_FACTS: u32 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    Driver,
    Registry,
}

impl Action {
    const fn wire(self) -> u32 {
        match self {
            Self::Driver => 1,
            Self::Registry => 2,
        }
    }

    const fn parse(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::Driver),
            2 => Some(Self::Registry),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    pub console_generation: u64,
    pub status_generation: u64,
    pub shell_generation: u64,
    pub outer_shell_job: u64,
    pub trigger_job: u64,
    pub trigger_wait_transaction: u64,
    pub action: Action,
    pub stage_nonce: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadyFacts {
    pub console_generation: u64,
    pub status_generation: u64,
    pub shell_generation: u64,
    pub attach_transaction: u64,
    pub stream_generation: u64,
    pub bundle_generation: u64,
}

impl ReadyFacts {
    const fn valid(self) -> bool {
        self.console_generation != 0
            && self.status_generation != 0
            && self.shell_generation != 0
            && self.attach_transaction != 0
            && self.stream_generation != 0
            && self.bundle_generation != 0
    }
}

impl Identity {
    const fn valid(self) -> bool {
        self.console_generation != 0
            && self.status_generation != 0
            && self.shell_generation != 0
            && self.outer_shell_job != 0
            && self.trigger_job != 0
            && self.trigger_wait_transaction != 0
            && self.stage_nonce != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Message {
    Quiesce(Identity),
    Quiesced(Identity),
    ReadyFacts(ReadyFacts),
}

impl Message {
    pub const fn identity(self) -> Option<Identity> {
        match self {
            Self::Quiesce(identity) | Self::Quiesced(identity) => Some(identity),
            Self::ReadyFacts(_) => None,
        }
    }

    const fn message_type(self) -> u32 {
        match self {
            Self::Quiesce(_) => TYPE_REQUEST,
            Self::Quiesced(_) => TYPE_ACK,
            Self::ReadyFacts(_) => TYPE_READY_FACTS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Length,
    Header,
    Reserved,
    Identity,
}

pub fn encode(message: Message) -> Result<[u8; FRAME_BYTES], Error> {
    let mut bytes = [0_u8; FRAME_BYTES];
    bytes[0..4].copy_from_slice(&MAGIC);
    put_u16(&mut bytes, 4, MAJOR);
    put_u16(&mut bytes, 6, MINOR);
    put_u32(&mut bytes, 8, message.message_type());
    put_u32(&mut bytes, 12, FRAME_BYTES as u32);
    match message {
        Message::Quiesce(identity) | Message::Quiesced(identity) => {
            if !identity.valid() {
                return Err(Error::Identity);
            }
            put_u64(&mut bytes, 24, identity.console_generation);
            put_u64(&mut bytes, 32, identity.status_generation);
            put_u64(&mut bytes, 40, identity.shell_generation);
            put_u64(&mut bytes, 48, identity.outer_shell_job);
            put_u64(&mut bytes, 56, identity.trigger_job);
            put_u64(&mut bytes, 64, identity.trigger_wait_transaction);
            put_u32(&mut bytes, 72, identity.action.wire());
            put_u64(&mut bytes, 80, identity.stage_nonce);
        }
        Message::ReadyFacts(facts) => {
            if !facts.valid() {
                return Err(Error::Identity);
            }
            put_u64(&mut bytes, 24, facts.console_generation);
            put_u64(&mut bytes, 32, facts.status_generation);
            put_u64(&mut bytes, 40, facts.shell_generation);
            put_u64(&mut bytes, 48, facts.attach_transaction);
            put_u64(&mut bytes, 56, facts.stream_generation);
            put_u64(&mut bytes, 64, facts.bundle_generation);
        }
    }
    Ok(bytes)
}

pub fn parse(bytes: &[u8]) -> Result<Message, Error> {
    if bytes.len() != FRAME_BYTES {
        return Err(Error::Length);
    }
    if bytes[0..4] != MAGIC
        || get_u16(bytes, 4) != MAJOR
        || get_u16(bytes, 6) != MINOR
        || get_u32(bytes, 12) != FRAME_BYTES as u32
    {
        return Err(Error::Header);
    }
    if get_u32(bytes, 16) != 0
        || get_u32(bytes, 20) != 0
        || get_u32(bytes, 76) != 0
        || get_u64(bytes, 88) != 0
    {
        return Err(Error::Reserved);
    }
    match get_u32(bytes, 8) {
        TYPE_REQUEST | TYPE_ACK => {
            let identity = Identity {
                console_generation: get_u64(bytes, 24),
                status_generation: get_u64(bytes, 32),
                shell_generation: get_u64(bytes, 40),
                outer_shell_job: get_u64(bytes, 48),
                trigger_job: get_u64(bytes, 56),
                trigger_wait_transaction: get_u64(bytes, 64),
                action: Action::parse(get_u32(bytes, 72)).ok_or(Error::Identity)?,
                stage_nonce: get_u64(bytes, 80),
            };
            if !identity.valid() {
                return Err(Error::Identity);
            }
            if get_u32(bytes, 8) == TYPE_REQUEST {
                Ok(Message::Quiesce(identity))
            } else {
                Ok(Message::Quiesced(identity))
            }
        }
        TYPE_READY_FACTS => {
            if bytes[72..96].iter().any(|byte| *byte != 0) {
                return Err(Error::Reserved);
            }
            let facts = ReadyFacts {
                console_generation: get_u64(bytes, 24),
                status_generation: get_u64(bytes, 32),
                shell_generation: get_u64(bytes, 40),
                attach_transaction: get_u64(bytes, 48),
                stream_generation: get_u64(bytes, 56),
                bundle_generation: get_u64(bytes, 64),
            };
            if !facts.valid() {
                return Err(Error::Identity);
            }
            Ok(Message::ReadyFacts(facts))
        }
        _ => Err(Error::Header),
    }
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn get_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn get_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn get_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> Identity {
        Identity {
            console_generation: 11,
            status_generation: 12,
            shell_generation: 13,
            outer_shell_job: 14,
            trigger_job: 15,
            trigger_wait_transaction: 16,
            action: Action::Driver,
            stage_nonce: 17,
        }
    }

    fn ready_facts() -> ReadyFacts {
        ReadyFacts {
            console_generation: 21,
            status_generation: 22,
            shell_generation: 23,
            attach_transaction: 24,
            stream_generation: 25,
            bundle_generation: 26,
        }
    }

    #[test]
    fn request_and_ack_round_trip_with_only_type_changed() {
        let request = encode(Message::Quiesce(identity())).unwrap();
        let ack = encode(Message::Quiesced(identity())).unwrap();
        assert_eq!(parse(&request), Ok(Message::Quiesce(identity())));
        assert_eq!(parse(&ack), Ok(Message::Quiesced(identity())));
        assert_eq!(&request[..8], &ack[..8]);
        assert_ne!(&request[8..12], &ack[8..12]);
        assert_eq!(&request[12..], &ack[12..]);
    }

    #[test]
    fn ready_facts_round_trip_and_reject_reserved_tail_bytes() {
        let bytes = encode(Message::ReadyFacts(ready_facts())).unwrap();
        assert_eq!(parse(&bytes), Ok(Message::ReadyFacts(ready_facts())));
        let mut altered = bytes;
        altered[72] = 1;
        assert_eq!(parse(&altered), Err(Error::Reserved));
    }

    #[test]
    fn malformed_headers_reserved_fields_and_identities_fail_closed() {
        let original = encode(Message::Quiesce(identity())).unwrap();
        for (offset, value) in [(0, 0), (4, 2), (6, 1), (8, 3), (12, 95)] {
            let mut bytes = original;
            bytes[offset] = value;
            assert!(parse(&bytes).is_err());
        }
        for offset in [16, 20, 76, 88] {
            let mut bytes = original;
            bytes[offset] = 1;
            assert_eq!(parse(&bytes), Err(Error::Reserved));
        }
        for offset in [24, 32, 40, 48, 56, 64, 80] {
            let mut bytes = original;
            bytes[offset..offset + 8].fill(0);
            assert_eq!(parse(&bytes), Err(Error::Identity));
        }
        assert_eq!(parse(&original[..95]), Err(Error::Length));
    }
}
