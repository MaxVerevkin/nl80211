use std::error::Error;

use crate::Attrs;
use crate::Bss;
use crate::Interface;
use crate::Nl80211Attr;
use crate::Nl80211Cmd;
use crate::Station;
use crate::NL_80211_GENL_NAME;
use crate::NL_80211_GENL_VERSION;
use neli::consts::socket::NlFamily;
use neli::err::DeError;

use neli::consts::{nl::NlmF, nl::Nlmsg};
use neli::genl::AttrTypeBuilder;
use neli::genl::Genlmsghdr;
use neli::genl::GenlmsghdrBuilder;
use neli::genl::NlattrBuilder;
use neli::genl::NoUserHeader;
use neli::nl::{NlPayload, Nlmsghdr};
use neli::router::asynchronous::NlRouter;
use neli::types::GenlBuffer;
use neli::utils::Groups;

/// A generic netlink socket to send commands and receive messages
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
pub struct AsyncSocket {
    router: NlRouter,
    family_id: u16,
}

impl AsyncSocket {
    /// Create a new nl80211 socket with netlink
    pub async fn connect() -> Result<Self, Box<dyn Error>> {
        let (router, _) = NlRouter::connect(NlFamily::Generic, None, Groups::empty()).await?;
        let family_id = router.resolve_genl_family(NL_80211_GENL_NAME).await?;
        Ok(Self { router, family_id })
    }

    async fn get_info_vec<T>(
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

        let mut receive_handle = self
            .router
            .send::<_, _, Nlmsg, Genlmsghdr<Nl80211Cmd, Nl80211Attr, NoUserHeader>>(
                self.family_id,
                NlmF::REQUEST | NlmF::DUMP,
                NlPayload::Payload(msghdr),
            )
            .await?;

        let mut retval = Vec::new();

        while let Some(response) = receive_handle.next().await {
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
    /// # use neli_wifi::AsyncSocket;
    /// # use std::error::Error;
    /// # async fn test() -> Result<(), Box<dyn Error>>{
    /// let wifi_interfaces = AsyncSocket::connect()?.get_interfaces_info().await?;
    /// for wifi_interface in wifi_interfacNlErrores {
    ///     println!("{:#?}", wifi_interface);
    /// }
    /// #   Ok(())
    /// # };
    ///```
    pub async fn get_interfaces_info(&mut self) -> Result<Vec<Interface>, Box<dyn Error>> {
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
    /// let mut socket = AsyncSocket::connect()?;
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
    ) -> Result<Vec<Station>, Box<dyn Error>> {
        self.get_info_vec(Some(interface_index), Nl80211Cmd::CmdGetStation)
            .await
    }

    pub async fn get_bss_info(&mut self, interface_index: i32) -> Result<Vec<Bss>, Box<dyn Error>> {
        self.get_info_vec(Some(interface_index), Nl80211Cmd::CmdGetScan)
            .await
    }
}

impl From<AsyncSocket> for NlRouter {
    /// Returns the underlying generic netlink socket
    fn from(sock: AsyncSocket) -> Self {
        sock.router
    }
}
