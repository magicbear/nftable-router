# nftable-router
Software Policy Router for nftables

# Icon Means
## Status ICON
### ALIVE:
> 🟩   - Global Lock Idle

> 🔴   - Process Dead

> 🟡   - Process Busying

> 🟩   - Process Idle > 30s

> 🟢   - Process Idle

### Proxy Test Status:
> ⚫ for Line

> ⬛ for Proxy

> ⚫   - N/A

> 🔴   - Failed

> 🟢   - <= 100ms

> 🔵   - <= 200ms

> 🟣   - <= 400ms

> 🟡   - <= 600ms

> 🟠   - <= 800ms

> 🟤   - > 800ms

# Config.json

- `ipdb_v4`				- Path for IPDB IPv4
- `ipdb_v6`				- Path for IPDB IPv6
- `nat_interfaces` 		- Interface for internal network (from this interfaces will be nat)
- `tunnel_ip`			- Tunnel IP, would be ignore to software router
- `allow_ecmp`			- Allow Equal Cost multi-path CIDR (TODO)
- `allow_ecmp_port` 	- Allow Equal Cost multi-path Ports (TODO)
- `ignore_print_domain`	- No output for Print domain
- `ignore_list`			- Ignore source CIDR for software router (such as internal router)
- `proxy`				- Line List
- `rules`				- Rules array for process (array for priority)
	- `from`			- match by source ip (highest priority)
	- `any`				- match any traffic
	- `resolve`			- match by resolved domain name
	- `cidr`			- match by target ip CIDR
	- `country_name`	- match by country name
	- `region_name`		- match by region name (such as `ALIDNS.COM`)
	- `city_name`		- match by city
	- `owner_domain`	- match by owner domain (such as `github.com`, `twitter.com`)
	- `isp_domain`		- match by ISP (such as `阿里云`, `阿里云/电信/联通/移动/教育网`)
	- `country_code`	- match by 2 char country code (such as `CN`)
	- `anycast`			- match by is anycast ip (only `` or `ANYCAST`)
	- `idc`				- match by is idc ip (only `` or `IDC`)
	- `base_station`	- match by is base_station ip
