# Upgrading from `netactuate/naapi`

`netactuate` replaces `netactuate/naapi`. The old client targets API v1 at
`https://vapi.netactuate.com`; this client exposes separate vAPI2 and vAPI3 clients and defaults
to the current production endpoints.

## What to edit

| Old | New |
| --- | --- |
| `pip install naapi` | `pip install netactuate` |
| `import naapi.api as api` | `from netactuate import Client, V3Client` |
| `api.NetActuateNodeDriver(API_KEY)` | `Client(api_key=API_KEY)` for vAPI2 or `V3Client(api_key=API_KEY)` for vAPI3 |
| `HOSTVIRTUAL_API_KEY` | `NETACTUATE_API_KEY` |
| API v1 host `https://vapi.netactuate.com` | vAPI2 `https://vapi2.netactuate.com/api/` and vAPI3 `https://vapi3.netactuate.com` |

## Call mapping

| `naapi` call | `netactuate` call | Notes |
| --- | --- | --- |
| `conn.servers()` | `Client().list_servers()` | Returns decoded `Server` objects rather than a raw response. |
| `conn.servers(mbpkgid)` | `Client().get_server(mbpkgid)` | `mbpkgid` is the server id. |
| `conn.bgp_sessions()` | No Python SDK replacement in this first release | Use the Ansible `netactuate.cloud.bgp_session` module or add SDK coverage first. |
| `conn.bgp_sessions(session_id)` | No Python SDK replacement in this first release | Mapping is not established in `netactuate`. |
| `conn.bgp_create_sessions(mbpkgid, group_id, ...)` | No Python SDK replacement in this first release | Mapping is not established in `netactuate`. |
| `conn.locations()` | No Python SDK replacement in this first release | Mapping is not established in `netactuate`. |
| `conn.os_list()` | No Python SDK replacement in this first release | Mapping is not established in `netactuate`. |
| `conn.plans(location)` | No Python SDK replacement in this first release | Mapping is not established in `netactuate`. |
| `conn.packages(mbpkgid)` | No Python SDK replacement in this first release | Mapping is not established in `netactuate`. |
| `conn.ipv4(mbpkgid)` | No Python SDK replacement in this first release | Mapping is not established in `netactuate`. |
| `conn.ipv6(mbpkgid)` | No Python SDK replacement in this first release | Mapping is not established in `netactuate`. |
| `conn.networkips(mbpkgid)` | No Python SDK replacement in this first release | Mapping is not established in `netactuate`. |
| `conn.summary(mbpkgid)` | No Python SDK replacement in this first release | Mapping is not established in `netactuate`. |
| `conn.start(mbpkgid)` | No Python SDK replacement in this first release | Mapping is not established in `netactuate`. |
| `conn.shutdown(mbpkgid, force)` | No Python SDK replacement in this first release | Mapping is not established in `netactuate`. |
| `conn.reboot(mbpkgid, force)` | No Python SDK replacement in this first release | Mapping is not established in `netactuate`. |
| `conn.rescue(mbpkgid, password)` | No Python SDK replacement in this first release | Mapping is not established in `netactuate`. |
| `conn.rescue_stop(mbpkgid)` | No Python SDK replacement in this first release | Mapping is not established in `netactuate`. |
| `conn.build(site, image, fqdn, passwd, mbpkgid)` | No Python SDK replacement in this first release | Mapping is not established in `netactuate`. |
| `conn.delete(mbpkgid, extra_params)` | No Python SDK replacement in this first release | Mapping is not established in `netactuate`. |
| `conn.unlink(mbpkgid)` | No Python SDK replacement in this first release | Mapping is not established in `netactuate`. |
| `conn.status(mbpkgid)` | No Python SDK replacement in this first release | Mapping is not established in `netactuate`. |
| `conn.bandwidth_report(mbpkgid)` | No Python SDK replacement in this first release | Mapping is not established in `netactuate`. |
| `conn.cancel(mbpkgid)` | No Python SDK replacement in this first release | Mapping is not established in `netactuate`. |
| `conn.buy(plan)` | No Python SDK replacement in this first release | Mapping is not established in `netactuate`. |
| `conn.buy_build(params)` | No Python SDK replacement in this first release | Mapping is not established in `netactuate`. |
| `conn.get_job(mbpkgid, job_id)` | No Python SDK replacement in this first release | Mapping is not established in `netactuate`. |
| `conn.get_jobs(mbpkgid)` | No Python SDK replacement in this first release | Mapping is not established in `netactuate`. |

## New vAPI3 calls

These calls did not exist in the old API v1 client:

| Resource | Call |
| --- | --- |
| VPCs | `V3Client().list_vpcs()`, `V3Client().get_vpc(id)` |
| Storage buckets | `V3Client().list_storage_buckets()`, `V3Client().get_storage_bucket(id)` |
| NKE clusters | `V3Client().list_nke_clusters()`, `V3Client().get_nke_cluster(id)` |

The old client returned raw HTTP responses. The new client returns typed objects and raises
distinguishable errors for not found and contract gated responses.
