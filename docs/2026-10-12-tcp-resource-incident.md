# TCP resource incident, 2026-10-12

## Evidence

The cloud host on SSH port 22 has approximately 1.7 GiB RAM and no swap. The previous boot recorded eight global OOM kills, all selecting opennofrp-server, at approximately 1.04–1.06 GiB anonymous resident memory. Rule 40 forwards public port 13991 to client 127.0.0.1:13991 with source preservation disabled. Logs record disabling it at 21:30:41, enabling it at 21:30:57, and a yamux write timeout at 21:32:12. The host rebooted at 22:07. No kernel memory sample or OOM event was retained for the 21:30 failure itself, so its exact allocation source is unproven.

## Fix

TCP listeners track accepted sockets, including backend opens, and close them when disabled. Tracking and shutdown synchronize acceptance to prevent a socket escaping cleanup. Reconciliation and rule snapshot publication are serialized. The server defaults to 512 simultaneous plain TCP forwards and a 300-second timeout with neither direction transferring data; both are configurable with server.max_tcp_connections and server.tcp_idle_timeout_seconds. Traffic in either direction refreshes the socket deadline. Half-close support is preserved.

The Linux server installer now gives the service MemoryHigh=40% and MemoryMax=50%. On this cloud host a persistent systemd drop-in sets MemoryHigh=512M, MemoryMax=768M and GOMEMLIMIT=384MiB. The hard limit contains future exhaustion within the service; it can still terminate and restart the service under overload, dropping its tunnels.

## Validation and deployment

Server and shared-library tests passed on Windows. Listener race tests passed on Linux. Linux go vet passed. Regression tests cover repeated disable/re-enable, established socket/stream closure, connection-slot recovery, exceeding the total limit, idle expiry, and accept-versus-disable races. The deployed binary SHA-256 is e922519daf7b46c485b8d2e885386c174460d45db0bc1f9f8bb7c93d85336a33. At 22:40 the client had reconnected, panel HTTP returned 303 to login, the forwarded SSH port worked, and vmstat showed no I/O pressure.

The previous binary and incident logs are in /opt/opennofrp/incident-backup-20261012 on the cloud host. The persistent limits are in /etc/systemd/system/opennofrp-server.service.d/50-resource-guard.conf. Roll back the binary by copying the backup to a temporary file beside /opt/opennofrp/opennofrp-server, replacing the installed file, and restarting opennofrp-server; keep the memory protection unless diagnosing it specifically.

## Remaining uncertainty

Short post-deployment observation cannot prove that the prior memory growth is completely eliminated. No heap profile exists for the hung process. The missing containerd executable and repeated containerd restart attempts are a separate host issue; this repair did not change that service.

## Root-cause follow-up

Sysstat history establishes severe file-page reclaim/refault thrashing: available memory fell from 46,792 KiB at 21:00 to 25,472 KiB at 21:30, 15,144 KiB at 21:48 and 11,884 KiB at 21:57. At 21:57 average page-in was 143,607.77 KiB/s, major faults 1,383.04/s and CPU iowait 77.11%. Swap activity stayed zero. Total sockets rose to 23,469, falling to 461 after reboot. The IPv4-only TCP count in sar is not a count of all connections; socket ownership by process was not retained. Recovery at 22:08 was due to the 22:07 reboot, before the repair deployment.

The previous binary was v0.5.0 at efcc6d314f11dad00ac05d6d0427d6b69855d2bd, not the newer local revision. It did not contain pkg/netrelay. Its relay failed to send FIN to yamux on public EOF, and its counting/protection wrappers did not forward CloseWrite. An isolated reproduction using that exact relay confirms that visitor EOF leaves the peer read and relay waiting until forced session teardown. This defect explains retained connection resources and is the leading cause of the observed long-term socket and anonymous-memory growth. The exact heap composition at the incident remains unknown. The final repair is identified as v0.5.0+tcpfix20261012, built from db8bb7e plus this task's changes.
