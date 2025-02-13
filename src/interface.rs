use crate::attr::{Attrs, Nl80211Attr};

use neli::attr::Attribute;
use neli::err::DeError;

/// A struct representing a wifi interface
#[non_exhaustive]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Interface {
    /// A netlink interface index. This index is used to fetch extra information with nl80211
    pub index: Option<i32>,
    /// Interface essid
    pub ssid: Option<Vec<u8>>,
    /// Interface MAC address
    pub mac: Option<Vec<u8>>,
    /// Interface name (u8, String)
    pub name: Option<Vec<u8>>,
    /// Interface frequency of the selected channel (MHz)
    pub frequency: Option<u32>,
    /// Interface chanel
    pub channel: Option<u32>,
    /// Interface transmit power level in signed mBm units.
    pub power: Option<u32>,
    /// index of wiphy to operate on, cf. /sys/class/ieee80211/<phyname>/index
    pub phy: Option<u32>,
    /// Wireless device identifier, used for pseudo-devices that don't have a netdev
    pub device: Option<u64>,
}

impl TryFrom<Attrs<'_, Nl80211Attr>> for Interface {
    type Error = DeError;

    fn try_from(attrs: Attrs<'_, Nl80211Attr>) -> Result<Self, Self::Error> {
        let mut res = Self::default();
        for attr in attrs.iter() {
            match attr.nla_type().nla_type() {
                Nl80211Attr::AttrIfindex => {
                    res.index = Some(attr.get_payload_as()?);
                }
                Nl80211Attr::AttrSsid => {
                    res.ssid = Some(attr.get_payload_as_with_len()?);
                }
                Nl80211Attr::AttrMac => {
                    res.mac = Some(attr.get_payload_as_with_len()?);
                }
                Nl80211Attr::AttrIfname => {
                    res.name = Some(attr.get_payload_as_with_len()?);
                }
                Nl80211Attr::AttrWiphyFreq => {
                    res.frequency = Some(attr.get_payload_as()?);
                }
                Nl80211Attr::AttrChannelWidth => {
                    res.channel = Some(attr.get_payload_as()?);
                }
                Nl80211Attr::AttrWiphyTxPowerLevel => {
                    res.power = Some(attr.get_payload_as()?);
                }
                Nl80211Attr::AttrWiphy => res.phy = Some(attr.get_payload_as()?),
                Nl80211Attr::AttrWdev => res.device = Some(attr.get_payload_as()?),
                _ => (),
            }
        }
        Ok(res)
    }
}

#[cfg(test)]
mod test_interface {
    use super::*;
    use crate::attr::Nl80211Attr::*;
    use neli::attr::AttrHandle;
    use neli::genl::{AttrTypeBuilder, Nlattr, NlattrBuilder};
    use neli::types::Buffer;

    fn new_attr(t: Nl80211Attr, d: Vec<u8>) -> Nlattr<Nl80211Attr, Buffer> {
        NlattrBuilder::default()
            .nla_type(
                AttrTypeBuilder::default()
                    .nla_network_order(true)
                    .nla_type(t)
                    .build()
                    .expect("Error constructing test attribute type {t:?}"),
            )
            .nla_payload(d)
            .build()
            .expect("Error constructing test attribute {t:?} with payload {d:?}")
    }

    #[test]
    fn test_parser() {
        let handler = vec![
            new_attr(AttrIfindex, vec![3, 0, 0, 0]),
            new_attr(AttrIfname, vec![119, 108, 112, 53, 115, 48]),
            new_attr(AttrWiphy, vec![0, 0, 0, 0]),
            new_attr(AttrIftype, vec![2, 0, 0, 0]),
            new_attr(AttrWdev, vec![1, 0, 0, 0, 0, 0, 0, 0]),
            new_attr(AttrMac, vec![255, 255, 255, 255, 255, 255]),
            new_attr(AttrWiphyFreq, vec![108, 9, 0, 0]),
            new_attr(AttrChannelWidth, vec![1, 0, 0, 0]),
            new_attr(AttrWiphyTxPowerLevel, vec![164, 6, 0, 0]),
            new_attr(AttrSsid, vec![101, 100, 117, 114, 111, 97, 109]),
        ];

        let interface: Interface = AttrHandle::new(handler.into_iter().collect())
            .try_into()
            .unwrap();
        let expected_interface = Interface {
            index: Some(3),
            ssid: Some(vec![101, 100, 117, 114, 111, 97, 109]),
            mac: Some(vec![255, 255, 255, 255, 255, 255]),
            name: Some(vec![119, 108, 112, 53, 115, 48]),
            frequency: Some(u32::from_le_bytes([108, 9, 0, 0])),
            channel: Some(u32::from_le_bytes([1, 0, 0, 0])),
            power: Some(u32::from_le_bytes([164, 6, 0, 0])),
            phy: Some(u32::from_le_bytes([0, 0, 0, 0])),
            device: Some(u64::from_le_bytes([1, 0, 0, 0, 0, 0, 0, 0])),
        };

        assert_eq!(interface, expected_interface)
    }
}
