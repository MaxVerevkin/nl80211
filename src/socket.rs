use std::error::Error;

use crate::attr::Nl80211Attr;
use crate::bss::Bss;
use crate::cmd::Nl80211Cmd;
use crate::interface::Interface;
use crate::station::Station;
use crate::{Attrs, NL_80211_GENL_NAME, NL_80211_GENL_VERSION};

use neli::consts::{nl::NlmF, nl::Nlmsg, socket::NlFamily};
use neli::err::DeError;
use neli::genl::{AttrTypeBuilder, Genlmsghdr, GenlmsghdrBuilder, NlattrBuilder, NoUserHeader};
use neli::nl::{NlPayload, Nlmsghdr};
use neli::router::synchronous::NlRouter;
use neli::types::GenlBuffer;
use neli::utils::Groups;

/// A generic netlink socket to send commands and receive messages
pub struct Socket {
    pub(crate) router: NlRouter,
    pub(crate) family_id: u16,
}

impl Socket {
    /// Create a new nl80211 socket with netlink
    pub fn connect() -> Result<Self, Box<dyn Error>> {
        let (sock, _) = NlRouter::connect(NlFamily::Generic, None, Groups::empty())?;
        let family_id = sock.resolve_genl_family(NL_80211_GENL_NAME)?;
        Ok(Self {
            router: sock,
            family_id,
        })
    }

    fn get_info_vec<T>(
        &mut self,
        interface_index: Option<i32>,
        cmd: Nl80211Cmd,
    ) -> Result<Vec<T>, Box<dyn Error>>
    where
        T: for<'a> TryFrom<Attrs<'a, Nl80211Attr>, Error = DeError>,
    {
        let msghdr = GenlmsghdrBuilder::<Nl80211Cmd, Nl80211Attr, NoUserHeader>::default()
            .cmd(cmd)
            .version(NL_80211_GENL_VERSION)
            .attrs({
                let mut attrs = GenlBuffer::new();
                if let Some(interface_index) = interface_index {
                    attrs.push(
                        NlattrBuilder::default()
                            .nla_type(
                                AttrTypeBuilder::default()
                                    .nla_type(Nl80211Attr::AttrIfindex)
                                    .build()
                                    .unwrap(),
                            )
                            .nla_payload(interface_index)
                            .build()
                            .unwrap(),
                    );
                }
                attrs
            })
            .build()
            .unwrap();

        let receive_handle = self
            .router
            .send::<_, _, Nlmsg, Genlmsghdr<Nl80211Cmd, Nl80211Attr, NoUserHeader>>(
                self.family_id,
                NlmF::REQUEST | NlmF::DUMP,
                NlPayload::Payload(msghdr),
            )?;

        let mut retval = Vec::new();

        for response in receive_handle {
            let response: Nlmsghdr<Nlmsg, Genlmsghdr<Nl80211Cmd, Nl80211Attr, NoUserHeader>> =
                response.unwrap();
            match Nlmsg::from(*response.nl_type()) {
                Nlmsg::Noop => (),
                Nlmsg::Error => panic!("Error"),
                Nlmsg::Done => break,
                _ => retval.push(
                    response
                        .get_payload()
                        .unwrap()
                        .attrs()
                        .get_attr_handle()
                        .try_into()?,
                ),
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
    pub fn get_interfaces_info(&mut self) -> Result<Vec<Interface>, Box<dyn Error>> {
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
    ) -> Result<Vec<Station>, Box<dyn Error>> {
        self.get_info_vec(Some(interface_index), Nl80211Cmd::CmdGetStation)
    }

    pub fn get_bss_info(&mut self, interface_index: i32) -> Result<Vec<Bss>, Box<dyn Error>> {
        self.get_info_vec(Some(interface_index), Nl80211Cmd::CmdGetScan)
    }
}

impl From<Socket> for NlRouter {
    /// Returns the underlying generic netlink router
    fn from(sock: Socket) -> Self {
        sock.router
    }
}
