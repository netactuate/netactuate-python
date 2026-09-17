# netactuate

`netactuate` is the NetActuate Python SDK. It provides separate clients for the two platform APIs:

- `Client` for vAPI2 at `https://vapi2.netactuate.com/api/`
- `V3Client` for vAPI3 at `https://vapi3.netactuate.com`

The client reads `NETACTUATE_API_KEY` when a key is not passed explicitly. API keys are sent as the
platform `key` query parameter and are redacted from errors.

## Install

```sh
python -m pip install .
```

## Use

```python
from netactuate import Client, V3Client

v2 = Client()
servers = v2.list_servers()
zones = v2.list_zones("master")

v3 = V3Client()
vpcs = v3.list_vpcs()
buckets = v3.list_storage_buckets()
clusters = v3.list_nke_clusters()

for vpc in vpcs:
    print(vpc.vpc_id, vpc.metadata.get("label", ""))

for bucket in buckets:
    print(bucket.bucket_id, bucket.metadata.get("label", ""))

for cluster in clusters:
    print(cluster.cluster_id, cluster.name)
```

Pass `api_key` and `base_url` to either client to override the environment and production endpoint:

```python
v3 = V3Client(api_key="...", base_url="https://example.test")
```

This wave covers servers, DNS zones and records, VPCs, storage buckets, and NKE clusters. The SDK
handles all vAPI3 list envelope forms used by the platform and follows pagination to the end.

API documentation lives at <https://netactuate.com/docs>.
