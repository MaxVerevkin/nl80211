use crate::attr::Nl80211Attr;
use crate::bss::Bss;
use crate::cmd::Nl80211Cmd;
use crate::interface::Interface;
use crate::station::Station;
use crate::{Attrs, NL_80211_GENL_NAME, NL_80211_GENL_VERSION};

use neli::consts::genl::{CtrlAttr, CtrlCmd};
use neli::consts::{nl::GenlId, nl::NlmF, nl::NlmFFlags, nl::Nlmsg, socket::NlFamily};
use neli::err::{DeError, NlError};
use neli::genl::{Genlmsghdr, Nlattr};
use neli::nl::{NlPayload, Nlmsghdr};
use neli::socket::NlSocketHandle;
use neli::types::GenlBuffer;

/// A generic netlink socket to send commands and receive messages
pub struct Socket {
    pub(crate) sock: NlSocketHandle,
    pub(crate) family_id: u16,
}

impl Socket {
    /// Create a new nl80211 socket with netlink
    pub fn connect() -> Result<Self, NlError<GenlId, Genlmsghdr<CtrlCmd, CtrlAttr>>> {
        let mut sock = NlSocketHandle::connect(NlFamily::Generic, None, &[])?;
        let family_id = sock.resolve_genl_family(NL_80211_GENL_NAME)?;
        Ok(Self { sock, family_id })
    }

    fn get_info_vec<T>(
        &mut self,
        interface_index: Option<i32>,
        cmd: Nl80211Cmd,
    ) -> Result<Vec<T>, NlError>
    where
        T: for<'a> TryFrom<Attrs<'a, Nl80211Attr>, Error = DeError>,
    {
        let msghdr = Genlmsghdr::<Nl80211Cmd, Nl80211Attr>::new(cmd, NL_80211_GENL_VERSION, {
            let mut attrs = GenlBuffer::new();
            if let Some(interface_index) = interface_index {
                attrs.push(
                    Nlattr::new(false, false, Nl80211Attr::AttrIfindex, interface_index).unwrap(),
                );
            }
            attrs
        });

        let nlhdr = {
            let len = None;
            let nl_type = self.family_id;
            let flags = NlmFFlags::new(&[NlmF::Request, NlmF::Dump]);
            let seq = None;
            let pid = None;
            let payload = NlPayload::Payload(msghdr);
            Nlmsghdr::new(len, nl_type, flags, seq, pid, payload)
        };

        self.sock.send(nlhdr)?;

        let iter = self
            .sock
            .iter::<Nlmsg, Genlmsghdr<Nl80211Cmd, Nl80211Attr>>(false);

        let mut retval = Vec::new();

        for response in iter {
            let response = response.unwrap();
            match response.nl_type {
                Nlmsg::Noop => (),
                Nlmsg::Error => panic!("Error"),
                Nlmsg::Done => break,
                _ => retval.push(
                    response
                        .nl_payload
                        .get_payload()
                        .unwrap()
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
    pub fn get_interfaces_info(&mut self) -> Result<Vec<Interface>, NlError> {
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
    pub fn get_station_info(&mut self, interface_index: i32) -> Result<Vec<Station>, NlError> {
        self.get_info_vec(Some(interface_index), Nl80211Cmd::CmdGetStation)
    }

    pub fn get_bss_info(&mut self, interface_index: i32) -> Result<Vec<Bss>, NlError> {
        self.get_info_vec(Some(interface_index), Nl80211Cmd::CmdGetScan)
    }
}

impl From<Socket> for NlSocketHandle {
    /// Returns the underlying generic netlink socket
    fn from(sock: Socket) -> Self {
        sock.sock
    }
}
