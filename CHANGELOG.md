# Changelog

## [1.2.0](https://github.com/Snipa22/go-tari-lib/compare/v1.1.0...v1.2.0) (2026-08-18)


### Features

* **p2p:** add ProbeOptions-aware ProbeChainMetadataWithOptions/ProbeGetPeersWithOptions ([27944a3](https://github.com/Snipa22/go-tari-lib/commit/27944a3455ae6b8c0498eb9fba84aa8e24da45d5))
* **p2p:** make the network wire byte configurable via ProbeOptions.NetworkByte ([01f3c61](https://github.com/Snipa22/go-tari-lib/commit/01f3c6186f75ea22a1c7021ae5f3cb760c62bc51))

## [1.1.0](https://github.com/Snipa22/go-tari-lib/compare/v1.0.0...v1.1.0) (2026-08-17)


### Features

* **nodeGRPC:** add GetSyncProgress and GetMempoolStats wrappers ([17e4068](https://github.com/Snipa22/go-tari-lib/commit/17e406874d3c8c43bc7aa587193cf62a83a2717b))
* **nodeGRPC:** add per-connection Client type, deprecate global-singleton package functions ([91d4148](https://github.com/Snipa22/go-tari-lib/commit/91d4148bd9b15022d61f49cf9b64e22a3c9fee5c))
* **p2p:** add RPC-over-P2P get_chain_metadata support ([057d564](https://github.com/Snipa22/go-tari-lib/commit/057d564d2b4b3899803937b011149fdb788c2280))
* **p2p:** add SOCKS5 proxy support for onion peer dialing ([d791a39](https://github.com/Snipa22/go-tari-lib/commit/d791a390a42a954692e8abf8b6c6093aedaf1d7e))
* **p2p:** add Tari Noise_XX P2P handshake client ([d4f7577](https://github.com/Snipa22/go-tari-lib/commit/d4f757768e932443c34374019e07f96c2267f687))
* **p2p:** implement t/dht/1 get_peers streaming RPC (method=10) ([2851c39](https://github.com/Snipa22/go-tari-lib/commit/2851c39a337a0d24beaf80635acb9cdd4c4246ca))


### Bug Fixes

* **p2p:** add missing identity exchange to ProbeChainMetadata ([6a1304f](https://github.com/Snipa22/go-tari-lib/commit/6a1304f9316e04ab6f0f7131997d5eefbc54bbcc))
* **p2p:** route RPC-over-P2P through Yamux multiplexing ([d663288](https://github.com/Snipa22/go-tari-lib/commit/d6632882070de994d0fba1f6bc47bbf9d6d1fd1b))
* **p2p:** sign outgoing PeerIdentityMsg to satisfy peer identity validation ([8f46998](https://github.com/Snipa22/go-tari-lib/commit/8f46998495462ecc308b03c1af30005801cbeb97))

## 1.0.0 (2026-08-16)


### Features

* extract nodeGRPC and walletGRPC wrapper packages from go-tari-grpc-lib ([8f59ec2](https://github.com/Snipa22/go-tari-lib/commit/8f59ec243091f2334bb47fae3b9d8f3b38cec180))
* scaffold go-tari-lib repo structure ([a725c93](https://github.com/Snipa22/go-tari-lib/commit/a725c930c44953b66ed961fa3e3d8d227afdac75))


### Bug Fixes

* remove local replace directive causing CI failure, resolve go-tari-grpc-lib/v3 from its published v3.2.0 tag ([defbf8e](https://github.com/Snipa22/go-tari-lib/commit/defbf8e2f1bac79aa91a8290d5ada6341a5999e9))
