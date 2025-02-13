use crate::attr::Nl80211Attr;
use crate::bss::Bss;
use crate::cmd::Nl80211Cmd;
use crate::interface::Interface;
use crate::station::Station;
use crate::{Attrs, NL_80211_GENL_NAME, NL_80211_GENL_VERSION};

use neli::consts::{nl::GenlId, nl::NlmF, socket::NlFamily};
use neli::err::DeError;
use neli::genl::{AttrTypeBuilder, Genlmsghdr, GenlmsghdrBuilder, NlattrBuilder};
use neli::nl::{NlPayload, Nlmsghdr};
use neli::router::synchronous::NlRouter;
use neli::types::GenlBuffer;
use neli::utils::Groups;

/// A generic netlink socket to send commands and receive messages
pub struct Socket {
    pub(crate) sock: NlRouter,
    pub(crate) family_id: u16,
}

impl Socket {
    /// Create a new nl80211 socket with netlink
    pub fn connect() -> Result<Self, Box<dyn std::error::Error>> {
        let (sock, _) = NlRouter::connect(NlFamily::Generic, None, Groups::empty())?;
        let family_id = sock.resolve_genl_family(NL_80211_GENL_NAME)?;
        Ok(Self { sock, family_id })
    }

    fn get_info_vec<T>(
        &mut self,
        interface_index: Option<i32>,
        cmd: Nl80211Cmd,
    ) -> Result<Vec<T>, Box<dyn std::error::Error>>
    where
        T: for<'a> TryFrom<Attrs<'a, Nl80211Attr>, Error = DeError>,
    {
        let mut attrs = GenlBuffer::new();
        if let Some(interface_index) = interface_index {
            let attrtype = AttrTypeBuilder::default()
                .nla_type(Nl80211Attr::AttrIfindex)
                .build()
                .unwrap();
            let nlattr = NlattrBuilder::default()
                .nla_type(attrtype)
                .nla_payload(interface_index)
                .build()
                .unwrap();
            attrs.push(nlattr);
        };
        let msghdr = GenlmsghdrBuilder::<Nl80211Cmd, Nl80211Attr>::default()
            .cmd(cmd)
            .version(NL_80211_GENL_VERSION)
            .attrs(attrs)
            .build()
            .unwrap();

        let recv = self
            .sock
            .send::<_, _, GenlId, Genlmsghdr<Nl80211Cmd, Nl80211Attr>>(
                self.family_id,
                NlmF::DUMP,
                NlPayload::Payload(msghdr),
            )?;

        let mut retval = Vec::new();

        for response in recv {
            let header: Nlmsghdr<GenlId, Genlmsghdr<Nl80211Cmd, Nl80211Attr>> = response.unwrap();
            if header.nl_type() == &GenlId::UnrecognizedConst(self.family_id) {
                if let NlPayload::Payload(p) = header.nl_payload() {
                    let attrs = p.attrs().get_attr_handle().try_into()?;
                    retval.push(attrs);
                }
            }
        }

        Ok(retval)
    }

    /// Get information for all your wifi interfaces
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use neli_wifi::Socket;
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>>{
    /// let wifi_interfaces = Socket::connect()?.get_interfaces_info()?;
    /// for wifi_interface in wifi_interfaces {
    ///     println!("{:#?}", wifi_interface);
    /// }
    /// #   Ok(())
    /// # }
    ///```
    pub fn get_interfaces_info(&mut self) -> Result<Vec<Interface>, Box<dyn std::error::Error>> {
        self.get_info_vec(None, Nl80211Cmd::CmdGetInterface)
    }

    /// Get access point information for a specific interface
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use neli_wifi::Socket;
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>>{
    /// // First of all we need to get wifi interface information to get more data
    /// let wifi_interfaces = Socket::connect()?.get_interfaces_info()?;
    /// for wifi_interface in wifi_interfaces {
    ///     if let Some(index) = wifi_interface.index {
    ///         // Then for each wifi interface we can fetch station information
    ///         for station_info in Socket::connect()?.get_station_info(index)? {
    ///             println!("{:#?}", station_info);
    ///         }
    ///      }
    /// }
    /// #   Ok(())
    /// # }
    ///```
    pub fn get_station_info(
        &mut self,
        interface_index: i32,
    ) -> Result<Vec<Station>, Box<dyn std::error::Error>> {
        self.get_info_vec(Some(interface_index), Nl80211Cmd::CmdGetStation)
    }

    pub fn get_bss_info(
        &mut self,
        interface_index: i32,
    ) -> Result<Vec<Bss>, Box<dyn std::error::Error>> {
        self.get_info_vec(Some(interface_index), Nl80211Cmd::CmdGetScan)
    }
}

impl From<Socket> for NlRouter {
    /// Returns the underlying generic netlink socket
    fn from(sock: Socket) -> Self {
        sock.sock
    }
}
