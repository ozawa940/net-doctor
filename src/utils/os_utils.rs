use log::debug;
use log::error;
use pnet::datalink::interfaces;
use pnet::datalink::NetworkInterface;



/**
 * Get active network interface
 */
pub fn get_active_interface(interace_name: &str) -> NetworkInterface {
    let interfaces = interfaces();

    let interface = interfaces.into_iter()
        .filter(|nic| -> bool {
            nic.name == interace_name
        })
        .next()
        .unwrap_or_else(|| {
            error!("OS-utils: Failed get network interface");
            panic!("failed get interface");
        });

    debug!("{:?}", interface);

    return interface;
}