//! Addresses: the three kinds, the three networks, and their base58 encoding.
//!
//! `specs/02-crypto.md` §5, `specs/05-blocks-and-transactions.md` §6, and the
//! prefix table in `specs/01-constants.md` §2.

use wow_crypto::base58::{decode_addr, encode_addr, Base58Error};
use wow_crypto::types::{AccountPublicAddress, Hash8, PublicKey};

/// `enum Network { Mainnet, Testnet, Stagenet, Fakechain }`.
///
/// `Fakechain` uses the **mainnet** config block (`get_config` maps
/// `FAKECHAIN => mainnet`), so it shares mainnet's prefixes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Network {
    Mainnet,
    Testnet,
    Stagenet,
    Fakechain,
}

impl Network {
    /// The network whose config block applies. `Fakechain` maps to `Mainnet`.
    pub fn config(self) -> Network {
        match self {
            Network::Fakechain => Network::Mainnet,
            other => other,
        }
    }

    /// `CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX`.
    pub fn address_prefix(self) -> u64 {
        match self {
            Network::Mainnet | Network::Fakechain => 4146,
            Network::Testnet => 53,
            Network::Stagenet => 24,
        }
    }

    /// `CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX`.
    pub fn integrated_prefix(self) -> u64 {
        match self {
            Network::Mainnet | Network::Fakechain => 6810,
            Network::Testnet => 54,
            Network::Stagenet => 25,
        }
    }

    /// `CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX`.
    pub fn subaddress_prefix(self) -> u64 {
        match self {
            Network::Mainnet | Network::Fakechain => 12208,
            Network::Testnet => 63,
            Network::Stagenet => 36,
        }
    }

    /// The name `get_info` reports.
    pub fn name(self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
            Network::Stagenet => "stagenet",
            Network::Fakechain => "fakechain",
        }
    }
}

/// What kind of address a prefix denotes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressKind {
    Standard,
    Integrated,
    Subaddress,
}

/// A decoded address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address {
    pub network: Network,
    pub kind: AddressKind,
    pub keys: AccountPublicAddress,
    /// Present only for an integrated address.
    pub payment_id: Option<Hash8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressError {
    Base58(Base58Error),
    /// The tag matched no network/kind pair.
    UnknownPrefix(u64),
    /// The body was not 64 bytes (standard/sub) or 72 (integrated).
    BadLength(usize),
    /// The address decoded but belongs to a different network.
    WrongNetwork {
        expected: Network,
        found: Network,
    },
}

impl core::fmt::Display for AddressError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AddressError::Base58(e) => write!(f, "{e}"),
            AddressError::UnknownPrefix(p) => write!(f, "unknown address prefix {p}"),
            AddressError::BadLength(n) => write!(f, "address body is {n} bytes"),
            AddressError::WrongNetwork { expected, found } => write!(
                f,
                "address is for {} but {} was expected",
                found.name(),
                expected.name()
            ),
        }
    }
}

impl std::error::Error for AddressError {}

impl From<Base58Error> for AddressError {
    fn from(e: Base58Error) -> Self {
        AddressError::Base58(e)
    }
}

impl Address {
    pub fn standard(network: Network, keys: AccountPublicAddress) -> Address {
        Address {
            network,
            kind: AddressKind::Standard,
            keys,
            payment_id: None,
        }
    }

    pub fn subaddress(network: Network, keys: AccountPublicAddress) -> Address {
        Address {
            network,
            kind: AddressKind::Subaddress,
            keys,
            payment_id: None,
        }
    }

    pub fn integrated(network: Network, keys: AccountPublicAddress, payment_id: Hash8) -> Address {
        Address {
            network,
            kind: AddressKind::Integrated,
            keys,
            payment_id: Some(payment_id),
        }
    }

    fn prefix(&self) -> u64 {
        match self.kind {
            AddressKind::Standard => self.network.address_prefix(),
            AddressKind::Integrated => self.network.integrated_prefix(),
            AddressKind::Subaddress => self.network.subaddress_prefix(),
        }
    }

    /// `get_account_address_as_str`.
    pub fn encode(&self) -> String {
        let mut data = Vec::with_capacity(72);
        data.extend_from_slice(&self.keys.spend_public_key.0);
        data.extend_from_slice(&self.keys.view_public_key.0);
        if let Some(pid) = self.payment_id {
            data.extend_from_slice(&pid);
        }
        encode_addr(self.prefix(), &data)
    }

    /// `get_account_address_from_str`, for any network.
    ///
    /// The legacy raw-hex path (`specs/02` §5, `specs/05` §6) is not supported;
    /// the reference marks it optional and nothing has produced one in years.
    pub fn decode(s: &str) -> Result<Address, AddressError> {
        let (tag, data) = decode_addr(s)?;
        let (network, kind) = classify(tag).ok_or(AddressError::UnknownPrefix(tag))?;

        let want = match kind {
            AddressKind::Integrated => 72,
            _ => 64,
        };
        if data.len() != want {
            return Err(AddressError::BadLength(data.len()));
        }

        let keys = AccountPublicAddress {
            spend_public_key: PublicKey(data[..32].try_into().unwrap()),
            view_public_key: PublicKey(data[32..64].try_into().unwrap()),
        };
        let payment_id = if kind == AddressKind::Integrated {
            Some(data[64..72].try_into().unwrap())
        } else {
            None
        };

        Ok(Address {
            network,
            kind,
            keys,
            payment_id,
        })
    }

    /// Decode, requiring a specific network.
    pub fn decode_for(s: &str, network: Network) -> Result<Address, AddressError> {
        let a = Address::decode(s)?;
        if a.network.config() != network.config() {
            return Err(AddressError::WrongNetwork {
                expected: network,
                found: a.network,
            });
        }
        Ok(a)
    }
}

/// Map a base58 tag back to `(network, kind)`.
fn classify(tag: u64) -> Option<(Network, AddressKind)> {
    for net in [Network::Mainnet, Network::Testnet, Network::Stagenet] {
        if tag == net.address_prefix() {
            return Some((net, AddressKind::Standard));
        }
        if tag == net.integrated_prefix() {
            return Some((net, AddressKind::Integrated));
        }
        if tag == net.subaddress_prefix() {
            return Some((net, AddressKind::Subaddress));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(a: u8, b: u8) -> AccountPublicAddress {
        AccountPublicAddress {
            spend_public_key: PublicKey([a; 32]),
            view_public_key: PublicKey([b; 32]),
        }
    }

    /// `specs/01` §2, and §15: "All address prefixes, ports and NETWORK_ID
    /// values match §2 exactly."
    #[test]
    fn prefixes_match_the_constants_table() {
        assert_eq!(Network::Mainnet.address_prefix(), 4146);
        assert_eq!(Network::Mainnet.integrated_prefix(), 6810);
        assert_eq!(Network::Mainnet.subaddress_prefix(), 12208);
        assert_eq!(Network::Testnet.address_prefix(), 53);
        assert_eq!(Network::Testnet.integrated_prefix(), 54);
        assert_eq!(Network::Testnet.subaddress_prefix(), 63);
        assert_eq!(Network::Stagenet.address_prefix(), 24);
        assert_eq!(Network::Stagenet.integrated_prefix(), 25);
        assert_eq!(Network::Stagenet.subaddress_prefix(), 36);
    }

    /// `get_config` maps `FAKECHAIN => mainnet`, so a regtest address is a
    /// mainnet address.
    #[test]
    fn fakechain_uses_the_mainnet_config() {
        assert_eq!(Network::Fakechain.address_prefix(), 4146);
        assert_eq!(Network::Fakechain.config(), Network::Mainnet);
        let a = Address::standard(Network::Fakechain, keys(1, 2));
        assert_eq!(
            Address::decode(&a.encode()).unwrap().network,
            Network::Mainnet
        );
    }

    #[test]
    fn roundtrip_every_kind_on_every_network() {
        for net in [Network::Mainnet, Network::Testnet, Network::Stagenet] {
            let k = keys(0x11, 0x22);
            for a in [
                Address::standard(net, k),
                Address::subaddress(net, k),
                Address::integrated(net, k, [0xab; 8]),
            ] {
                let s = a.encode();
                let back = Address::decode(&s).unwrap_or_else(|e| panic!("{s}: {e}"));
                assert_eq!(back, a);
                assert_eq!(Address::decode_for(&s, net).unwrap(), a);
            }
        }
    }

    /// `specs/02` §5: a mainnet standard/sub address is 97 characters and an
    /// integrated one is 108. `specs/14` §3.6 depends on telling them apart by
    /// length.
    #[test]
    fn mainnet_address_lengths() {
        let k = keys(3, 4);
        assert_eq!(Address::standard(Network::Mainnet, k).encode().len(), 97);
        assert_eq!(Address::subaddress(Network::Mainnet, k).encode().len(), 97);
        assert_eq!(
            Address::integrated(Network::Mainnet, k, [0; 8])
                .encode()
                .len(),
            108
        );
    }

    /// Wownero's mainnet prefix 4146 is a 2-byte varint, which is what makes
    /// the address 97 characters rather than Monero's 95.
    #[test]
    fn mainnet_prefix_is_a_two_byte_varint() {
        let mut v = Vec::new();
        wow_serialize::varint::write_varint(&mut v, 4146);
        assert_eq!(v.len(), 2);
        // 2 + 64 + 4 = 70 bytes -> 8 full blocks + a 6-byte tail -> 88 + 9 = 97.
        assert_eq!(
            70 / 8 * 11 + wow_crypto::base58::ENCODED_BLOCK_SIZES[70 % 8],
            97
        );
    }

    #[test]
    fn rejects_a_wrong_network() {
        let s = Address::standard(Network::Testnet, keys(1, 1)).encode();
        assert!(matches!(
            Address::decode_for(&s, Network::Mainnet),
            Err(AddressError::WrongNetwork { .. })
        ));
    }

    #[test]
    fn rejects_corruption_and_junk() {
        let s = Address::standard(Network::Mainnet, keys(1, 1)).encode();
        assert!(Address::decode(&s).is_ok());

        // A flipped character breaks the checksum.
        let mut c: Vec<char> = s.chars().collect();
        c[10] = if c[10] == '1' { '2' } else { '1' };
        let t: String = c.into_iter().collect();
        assert!(Address::decode(&t).is_err());

        for junk in ["", "x", "not an address", "111111111111"] {
            assert!(Address::decode(junk).is_err(), "{junk:?} should not decode");
        }
    }

    /// An unknown tag must not be silently accepted as some network's.
    #[test]
    fn rejects_unknown_prefixes() {
        let s = wow_crypto::base58::encode_addr(9999, &[0u8; 64]);
        assert!(matches!(
            Address::decode(&s),
            Err(AddressError::UnknownPrefix(9999))
        ));
        // Monero's own mainnet prefix (18) must not decode as Wownero.
        let s = wow_crypto::base58::encode_addr(18, &[0u8; 64]);
        assert!(matches!(
            Address::decode(&s),
            Err(AddressError::UnknownPrefix(18))
        ));
    }

    /// A body of the wrong length for its tag is rejected: an integrated tag
    /// with 64 bytes, or a standard tag with 72.
    #[test]
    fn rejects_a_body_of_the_wrong_length() {
        let s = wow_crypto::base58::encode_addr(6810, &[0u8; 64]);
        assert!(matches!(
            Address::decode(&s),
            Err(AddressError::BadLength(64))
        ));
        let s = wow_crypto::base58::encode_addr(4146, &[0u8; 72]);
        assert!(matches!(
            Address::decode(&s),
            Err(AddressError::BadLength(72))
        ));
    }

    #[test]
    fn never_panics() {
        let mut x: u64 = 0xdead_beef_cafe_1234;
        for len in 0..140usize {
            let s: String = (0..len)
                .map(|_| {
                    x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
                    char::from(33u8 + ((x >> 33) % 94) as u8)
                })
                .collect();
            let _ = Address::decode(&s);
        }
    }
}
