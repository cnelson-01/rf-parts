# rf-parts

## w1700k-ble-sniffer

[`w1700k-ble-sniffer/`](w1700k-ble-sniffer/README.md) is a wideband Bluetooth LE sniffer for the
W1700K receiver ([github.com/h0m3us3r/w1700k-sdr](https://github.com/h0m3us3r/w1700k-sdr)). At
160 Msps around 2441 MHz it decodes all 40 BLE channels at once: advertising, AUX packets, and
every data packet of every connection, with no channel hopping to follow. It writes into the same
sqlite table (`ble_packets`) as [`simple-plutoble-scanner/`](simple-plutoble-scanner/), and comes
with a live web UI. Start it with `w1700k-ble-sniffer/run.sh --web`.
