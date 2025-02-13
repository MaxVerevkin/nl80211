use crate::Attrs;
use crate::Bss;
use crate::Interface;
use crate::Nl80211Attr;
use crate::Nl80211Cmd;
use crate::Station;
use crate::{NL_80211_GENL_NAME, NL_80211_GENL_VERSION};
use neli::err::DeError;

use neli::consts::{nl::GenlId, nl::NlmF, socket::NlFamily};
use neli::genl::{AttrTypeBuilder, Genlmsghdr, GenlmsghdrBuilder, NlattrBuilder};
use neli::nl::{NlPayload, Nlmsghdr};
use neli::router::asynchronous::NlRouter;
use neli::types::GenlBuffer;
use neli::utils::Groups;

/// A generic netlink socket to send commands and receive messages
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
pub struct AsyncSocket {
    sock: NlRouter,
    family_id: u16,
}

impl AsyncSocket {
    /// Create a new nl80211 socket with netlink
    pub async fn connect() -> Result<Self, Box<dyn std::error::Error>> {
        let (sock, _) = NlRouter::connect(NlFamily::Generic, None, Groups::empty()).await?;
        let family_id = sock.resolve_genl_family(NL_80211_GENL_NAME).await?;
        Ok(Self { sock, family_id })
    }

    async fn get_info_vec<T>(
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

        let mut recv = self
            .sock
            .send::<_, _, GenlId, Genlmsghdr<Nl80211Cmd, Nl80211Attr>>(
                self.family_id,
                NlmF::DUMP,
                NlPayload::Payload(msghdr),
            )
            .await?;

        let mut retval = Vec::new();

        while let Some(response) = recv.next().await {
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
    /// # use neli_wifi::AsyncSocket;
    /// # use std::error::Error;
    /// # async fn test() -> Result<(), Box<dyn Error>>{
    /// let wifi_interfaces = AsyncSocket::connect().await?.get_interfaces_info().await?;
    /// for wifi_interface in wifi_interfaces {
    ///     println!("{:#?}", wifi_interface);
    /// }
    /// #   Ok(())
    /// # };
    ///```
    pub async fn get_interfaces_info(
        &mut self,
    ) -> Result<Vec<Interface>, Box<dyn std::error::Error>> {
        self.get_info_vec(None, Nl80211Cmd::CmdGetInterface).await
    }

    /// Get access point information for a specific interface
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use neli_wifi::AsyncSocket;
    /// # use std::error::Error;
    /// # async fn test() -> Result<(), Box<dyn Error>> {
    /// let mut socket = AsyncSocket::connect().await?;
    /// // First of all we need to get wifi interface information to get more data
    /// let wifi_interfaces = socket.get_interfaces_info().await?;
    /// for wifi_interface in wifi_interfaces {
    ///     if let Some(index) = wifi_interface.index {
    ///         // Then for each wifi interface we can fetch station information
    ///         for station_info in socket.get_station_info(index).await? {
    ///             println!("{:#?}", station_info);
    ///         }
    ///     }
    /// }
    /// #   Ok(())
    /// # }
    ///```
    pub async fn get_station_info(
        &mut self,
        interface_index: i32,
    ) -> Result<Vec<Station>, Box<dyn std::error::Error>> {
        self.get_info_vec(Some(interface_index), Nl80211Cmd::CmdGetStation)
            .await
    }

    pub async fn get_bss_info(
        &mut self,
        interface_index: i32,
    ) -> Result<Vec<Bss>, Box<dyn std::error::Error>> {
        self.get_info_vec(Some(interface_index), Nl80211Cmd::CmdGetScan)
            .await
    }
}

impl From<AsyncSocket> for NlRouter {
    /// Returns the underlying generic netlink socket
    fn from(sock: AsyncSocket) -> Self {
        sock.sock
    }
}
