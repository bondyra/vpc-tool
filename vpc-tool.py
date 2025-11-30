#!/usr/bin/env python3
import argparse
import sys
import ipaddress
from colorama import Fore, Style
from contextlib import ExitStack
from concurrent.futures import ThreadPoolExecutor, as_completed

import boto3
import json
from tqdm import tqdm


IS_DEBUG = False


def _debug(txt):
    if IS_DEBUG:
        print(Style.DIM + "[debug] " + txt + Style.RESET_ALL)


def _err(txt):
    print(Fore.RED + txt + Style.RESET_ALL)
    exit(1)


def _just_one(items, on_zero, on_many):
    if not len(items):
        on_zero()
        return None
    if len(items) > 1:
        on_many()
        return None
    return items[0]


def _warn(txt):
    print(Fore.YELLOW + txt + Style.RESET_ALL)


def _print_route(source, destination, target, via, suffix=""):
    print(f"{source} -> " + target + f" via {via} route {destination}{suffix}")


def _colored(txt, fore):
    return fore + txt + Style.RESET_ALL


def cmd_range(args):
    try:
        n = ipaddress.ip_network(args.cidr, strict=False)
        print(f"{n[0]} - {n[-1]} ({n.num_addresses} IPs)")
    except Exception as e:
        _err(f"Something went wrong: {e}")


_default_session = boto3.Session()
_provider_cache = {}


def _get_cached_client(profile, region, client_name):
    key = (profile, region, client_name)

    if key not in _provider_cache:
        session = boto3.Session(profile_name=profile, region_name=region)
        _provider_cache[key] = session.client(client_name)

    return _provider_cache[key]


def _aws_call(profile, region, client_name, method_name, response_field, id_field, paginated):
    client = _get_cached_client(profile, region, client_name)
    if paginated:
        paginator = client.get_paginator(method_name)
        for page in paginator.paginate():
            for r in page.get(response_field):
                yield {"__id": r.get(id_field), **r}
    # elif stupidly_paginated:
    #     next_token = None
    #     while True:
    #         kwargs = {"MaxResults": 100}
    #         if next_token is not None:
    #             kwargs["NextToken"] = next_token
    #         response = client.describe_prefix_lists(**kwargs)
    #         for r in response.get(response_field):
    #             yield {"__id": r.get(id_field), **r}
    #         next_token = response.get("NextToken")
    #         if not next_token:
    #             break
    else:
        response = getattr(client, method_name)()
        for r in response.get(response_field):
            yield {"__id": r.get(id_field), **r}


def _list_all_routes(client, tgw_rtb_id):
    token = None
    while True:
        args = {
            "TransitGatewayRouteTableId": tgw_rtb_id,
            "Filters": [{"Name": "type", "Values": ["static", "propagated"]}],
        }
        if token:
            args["NextToken"] = token
        resp = client.search_transit_gateway_routes(**args)
        yield from resp["Routes"]
        token = resp.get("NextToken")
        if not token:
            break


def _describe_tgw_route_table(profile, region):
    client = _get_cached_client(profile, region, "ec2")
    for rt in _aws_call(profile, region, "ec2", "describe_transit_gateway_route_tables", "TransitGatewayRouteTables", "TransitGatewayRouteTableId", True):
        routes = list(_list_all_routes(client, rt["TransitGatewayRouteTableId"]))
        yield {"Routes": routes, **rt}


funcs = {
    "vpc": (lambda profile, region: _aws_call(profile, region, "ec2", "describe_vpcs", "Vpcs", "VpcId", True), Fore.BLUE),
    "subnet": (lambda profile, region: _aws_call(profile, region, "ec2", "describe_subnets", "Subnets", "SubnetId", True), Fore.BLUE),
    "route_table": (lambda profile, region: _aws_call(profile, region, "ec2", "describe_route_tables", "RouteTables", "RouteTableId", True), Fore.BLUE),
    "internet_gateway": (lambda profile, region: _aws_call(profile, region, "ec2", "describe_internet_gateways", "InternetGateways", "InternetGatewayId", True), Fore.YELLOW),
    "nat_gateway": (lambda profile, region: _aws_call(profile, region, "ec2", "describe_nat_gateways", "NatGateways", "NatGatewayId", True), Fore.BLUE),
    "prefix_list": (lambda profile, region: _aws_call(profile, region, "ec2", "describe_prefix_lists", "PrefixLists", "PrefixListId", True), Fore.BLUE),
    "vpc_endpoint": (lambda profile, region: _aws_call(profile, region, "ec2", "describe_vpc_endpoints", "VpcEndpoints", "VpcEndpointId", True), Fore.BLUE),
    "vpc_peering": (lambda profile, region: _aws_call(profile, region, "ec2", "describe_vpc_peering_connections", "VpcPeeringConnections", "VpcPeeringConnectionId", True), Fore.CYAN),
    "virtual_gateway": (lambda profile, region: _aws_call(profile, region, "directconnect", "describe_virtual_gateways", "virtualGateways", "virtualGatewayId", False), Fore.YELLOW),
    "tgw": (lambda profile, region: _aws_call(profile, region, "ec2", "describe_transit_gateways", "TransitGateways", "TransitGatewayId", True), Fore.MAGENTA),
    "tgw_route_table": (_describe_tgw_route_table, Fore.MAGENTA),  # needs two calls - describe tgw route table + search routes
    "tgw_attachment": (lambda profile, region: _aws_call(profile, region, "ec2", "describe_transit_gateway_attachments", "TransitGatewayAttachments", "TransitGatewayAttachmentId", True), Fore.MAGENTA),
}
# TODO: tgw


def _aws_all(regions, max_workers=20):
    profiles = _default_session.available_profiles
    print(f"Describing {len(funcs)} resource types for each of {len(profiles)} AWS profiles times {len(regions)} regions. This could take a while...")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for name, (func, clr) in funcs.items():
            for profile in profiles:
                for region in regions:
                    future = executor.submit(func, profile, region)
                    futures[future] = (profile, region, name, clr)

        for future in tqdm(as_completed(futures), total=len(futures)):
            profile, region, name, clr = futures[future]
            try:
                result = future.result()
            except Exception:
                pass
            for r in result:
                yield {
                    "__func": name, "__profile": profile, "__region": region,
                    "__display": f"{r["__id"]} ({name} @ {profile}/{region})",
                    "__clr": clr,
                    **r
                }


def cmd_scan(args):
    results = _aws_all(args.regions)
    with ExitStack() as stack:
        files = {name: stack.enter_context(open(f".vpc-tool-cache-{name}", "w")) for name in funcs}
        for r in results:
            files[r["__func"]].write(json.dumps(r, default = lambda o: o.__str__))
            files[r["__func"]].write("\n")
    print("Saved outputs to $PWD/.vpc-tool-cache-<RESOURCE_TYPE> files")


def _load_context():
    try:
        context = {}
        for name in funcs:
            with open(f".vpc-tool-cache-{name}", "r") as f:
                context[name] = [json.loads(l) for l in f.readlines()]
        return context
    except:
        _err("Cannot run 'trace' - please run 'scan' command first.")


### TRACE


def cmd_trace(args):
    try:
        _validate_ip_or_cidr(args.source)
        _validate_ip_or_cidr(args.target)
    except ValueError as e:
        _err(f"Validation error: {e}")
    context = _load_context()
    destination, target_id, route_table_id = _find_route_for_ip(context, args.source, args.target)
    _process_route(context, args.source, destination, target_id, route_table_id, args.target)


def _process_route(context, source, destination, target_id, route_table_id, ultimate_target):
    if target_id == "local":
        _print_route(source, destination, _colored(target_id, Fore.GREEN), route_table_id)
    else:
        obj = _just_one(
            _get_obj_for_id(context, target_id),
            on_zero=lambda: _print_route(source, destination, f"{target_id} (idk what's this)", route_table_id, Fore.RED),
            on_many=lambda: _print_route(source, destination, f"{target_id} (multiple things point to it for some reason)", route_table_id, Fore.RED)
        )
        _print_route(source, destination, _colored(obj["__display"], obj["__clr"]), route_table_id)
        if obj["__func"] == "tgw":
            tgw_attachment = _get_tgw_attachment_for_ip(context, obj, source)
            _trace_transit_gateway(context, obj, tgw_attachment, ultimate_target)

def _validate_ip_or_cidr(value):
    try:
        ipaddress.ip_address(value)
        return
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise

####### TRACE LOGIC
def _find_vpc_for_ip(context, ip):
    ret = _most_specific_match(ip, context["vpc"], lambda s: s["CidrBlock"])
    _debug(f"Found VPC for IP {ip} - {ret["__display"]}")
    return ret


def _find_subnet_for_ip(context, ip):
    ret = _most_specific_match(ip, context["subnet"], lambda s: s["CidrBlock"])
    _debug(f"Found subnet for IP {ip} - {ret["__display"]}")
    return ret


def _get_obj_for_id(context, id):
    return [i for lst in context.keys() for i in context.get(lst) if i["__id"] == id]


def _most_specific_match(ip_str, items, cidr_fun):
    ip = ipaddress.ip_address(ip_str)

    best = None
    best_prefix = -1

    for _i, item in enumerate(items):
        try:
            net = ipaddress.ip_network(cidr_fun(item), strict=False)
        except ValueError:
            continue  # skip invalid CIDRs
        if ip in net and net.prefixlen > best_prefix:
            best = items[_i]
            best_prefix = net.prefixlen
    if not best:
        _err(f"Cannot find any match for ip {ip_str}")

    return best


def _find_route_table_for_subnet(context, subnet):
    vpc_id, subnet_id = subnet["VpcId"], subnet["SubnetId"]
    vpc_route_tables = [r for r in context["route_table"] if r["VpcId"] == vpc_id]
    explicitly_assigned_route_tables = [r for r in context["route_table"] if any(a.get("SubnetId") == subnet_id for a in r["Associations"])]
    if not explicitly_assigned_route_tables:
        main_route_table = _just_one(
            [r for r in vpc_route_tables if any(a["Main"] for a in r["Associations"])], 
            on_zero=lambda: _err(f"VPC {vpc_id} has no main route tables, wtf"), on_many=lambda: _err(f"VPC {vpc_id} has many main route tables, wtf")
        )
        _debug(f"Subnet {subnet_id} uses main VPC route table: {main_route_table["__display"]}")
        return main_route_table
    if len(explicitly_assigned_route_tables) > 1:
        _err(f"Subnet {subnet_id} is explicitly assigned to multiple route tables: {[r["RouteTableId"] for r in explicitly_assigned_route_tables]}, how's that possible?")
    _debug(f"Subnet {subnet_id} has explicit association to following route table: {explicitly_assigned_route_tables[0]["__display"]}")
    return explicitly_assigned_route_tables[0]


def _find_route_table_for_vpc(context, vpc):
    vpc_id = vpc["__id"]
    vpc_route_tables = [r for r in context["route_table"] if r["VpcId"] == vpc_id]
    main_route_table = _just_one(
        [r for r in vpc_route_tables if any(a["Main"] for a in r["Associations"])], 
        on_zero=lambda: _err(f"VPC {vpc_id} has no main route tables, wtf"), 
        on_many=lambda: _err(f"VPC {vpc_id} has many main route tables, wtf")
    )
    return main_route_table


def _simplified_route_table(context, route_table):
    routes = route_table.get("Routes", [])
    prefix_list_id_to_cidrs = {
        pl_id: list(_expanded_prefix_list(context, pl_id)) 
        for pl_id in set(route["PrefixListId"] for route in routes if route.get("PrefixListId"))
    }
    for _i, route in enumerate(routes):
        target_id = (
            route.get("TransitGatewayId")
            or route.get("VpcPeeringConnectionId")
            or route.get("VpcEndpointId")
            or route.get("NetworkInterfaceId")
            or route.get("GatewayId")
            or route.get("InstanceId")
        )

        if not target_id:
            continue
        if route["State"] != "active":
            _debug(f"Ignoring route {_i} in {route_table["__display"]} because its state is \"{route["State"]}\"")
            continue
            
        if "DestinationCidrBlock" in route:
            yield {"destination": route["DestinationCidrBlock"], "target": target_id, "state": route["State"], "route_table_id": route_table["RouteTableId"]}
        elif "DestinationIpv6CidrBlock" in route:
            yield {"destination": route["DestinationIpv6CidrBlock"], "target": target_id, "state": route["State"], "route_table_id": route_table["RouteTableId"]}
        elif "DestinationPrefixListId" in route:
            for cidr in prefix_list_id_to_cidrs[route["DestinationPrefixListId"]]:
                yield {"destination": cidr, "target": target_id, "state": route["State"], "route_table_id": route_table["RouteTableId"]}
        else:
            _err(f"Route {_i} in route table {route_table["RouteTableId"]} doesn't have any supported destination")


def _find_route_for_vpc(context, vpc, target):
    route_table = _find_route_table_for_vpc(context, vpc)
    return _get_match_in_route_table(context, route_table, target)


def _find_route_for_ip(context, source, target):
    subnet = _find_subnet_for_ip(context, source)
    route_table = _find_route_table_for_subnet(context, subnet)
    return _get_match_in_route_table(context, route_table, target)


def _get_match_in_route_table(context, route_table, target):
    s_route_table = list(_simplified_route_table(context, route_table))
    m = _most_specific_match(target, s_route_table, lambda r: r["destination"])
    _debug(f"Most specific match for IP {target} in the route table is: {m}")
    return (m["destination"], m["target"], m["route_table_id"])


def _expanded_prefix_list(context, pl_id):
    prefix_lists = [pl for pl in context["prefix_list"] if pl["PrefixListId"] == pl_id]
    if not prefix_lists:
        _err(f"I cannot find prefix list {pl_id} anywhere. WTF is it?")
    if len(prefix_lists) > 0:
        _warn(f"Found multiple prefix lists for single id {pl_id}. Looks like 'scan' command sucks, anyways choosing the first one")

    entries = prefix_lists[0]["Entries"]

    for _i, entry in enumerate(entries):
        cidr = entry.get("Cidr")
        if not cidr:
            _err(f"Prefix list {pl_id} entry {_i} doesn't have any CIDR. How the hell it works then?")
        yield cidr


def _get_tgw_attachment_for_ip(context, tgw, source):
    vpc = _find_vpc_for_ip(context, source)
    tgw_attachment = _get_tgw_attachment(context, tgw, vpc)
    return tgw_attachment


def _get_tgw_attachment(context, tgw, vpc):
    ret = _just_one(
        [a for a in context["tgw_attachment"] if a["TransitGatewayId"] == tgw["__id"] and a["ResourceId"] == vpc["__id"]],
        on_zero=lambda: _err(f"{vpc["__display"]} is not attached to {tgw["__display"]}. There must be a bug in this tool or VPC's route table is not in sync with TGW"),
        on_many=lambda: _err(f"{vpc["__display"]} is attached multiple times to {tgw["__display"]}. This shouldn't be possible, indicates a bug in scan command")
    )
    _debug(f"Found association for {vpc["__display"]} in {tgw["__display"]}: {ret["__display"]}")
    return ret

def _get_tgw_route_table(context, tgw, tgw_attachment):
    rtb_id = None
    if tgw_attachment.get("Association", {}).get("TransitGatewayRouteTableId") and tgw_attachment.get("Association", {}).get("State") == "associated":
        rtb_id = tgw_attachment["Association"]["TransitGatewayRouteTableId"]
        _debug(f"{tgw_attachment["__display"]} is using explicitly associated route table {rtb_id}")
    else:
        rtb_id = tgw["AssociationDefaultRouteTableId"]
        _debug(f"{tgw_attachment["__display"]} is using default association route table {rtb_id}")
    rtb = _just_one(
        [r for r in context["tgw_route_table"] if r["__id"] == rtb_id],
        on_zero=lambda: _err(f"{tgw_attachment["__display"]} is using route table {rtb_id}, but it doesn't exist? This shouldn't be possible, indicates a bug in scan command"),
        on_many=lambda: _err(f"Found multiple route tables for {rtb_id}. This shouldn't be possible, indicates a bug in scan command")
    )
    _debug(f"Found route table for {tgw_attachment["__display"]}: {rtb["__display"]}")
    return rtb


def _trace_transit_gateway(context, tgw, tgw_attachment, target):
    route_table = _get_tgw_route_table(tgw, tgw_attachment)
    s_route_table = list(_simplified_tgw_route_table(route_table))
    m = _most_specific_match(target, [s for s in s_route_table], lambda s: s["destination"])
    if m["ResourceType"] == "tgw-peering":
        peer = _just_one(
            _get_obj_for_id(context, m["ResourceId"]),
            on_zero=lambda: _err(f"Target {target} is routed to TGW {m["ResourceId"]}, but no info about this TGW. Re-run scan with wider range"),
            on_many=lambda: _err(f"Target {target} is routed to TGW {m["ResourceId"]}, but there are multiple TGWs with this ID. Bug in scan command")
        )
        _print_route(target, m["destination"], _colored(peer["__display"], peer["__clr"]), route_table["__id"], _colored(route_table["__id"], Fore.MAGENTA))
        peer_tgwa_id = m["TransitGatewayAttachmentId"]
        peer_attachment = _just_one(
            _get_obj_for_id(context, peer_tgwa_id),
            on_zero=lambda: _err(f"{peer["__display"]} has attachment {peer_tgwa_id}, but no info about this attachment. Re-run scan with wider range"),
            on_many=lambda: _err(f"{peer["__display"]} has attachment {peer_tgwa_id}, but there are multiple attachments with this ID. Bug in scan command")
        )
        _trace_transit_gateway(context, peer, peer_attachment, target)  # recurse on next hop
    elif m["ResourceType"] == "vpc":
        v = _just_one(
            _get_obj_for_id(context, m["ResourceId"]),
            on_zero=lambda: _err(f"Target {target} is routed to VPC {m["ResourceId"]}, but no info about this VPC. Re-run scan with wider range"),
            on_many=lambda: _err(f"Target {target} is routed to VPC {m["ResourceId"]}, but there are multiple VPCs with this ID. Bug in scan command")
        )
        _print_route(target, m["destination"], _colored(v["__display"], v["__clr"]), route_table["__id"], _colored(route_table["__id"], Fore.MAGENTA))
        x_destination, x_target_id, x_route_table_id = _find_route_for_vpc(context, v, target)
        _process_route(context, target, x_destination, x_target_id, x_route_table_id, target)
    else:
        _print_route(target, m["destination"], _colored(f"{m["ResourceId"]} ({m["ResourceType"]})", Fore.MAGENTA), route_table["__id"], _colored(" Unsupported type of TGW attachment - tracing stopped", Fore.RED))


def _simplified_tgw_route_table(context, route_table):
    routes = route_table.get("Routes", [])
    prefix_list_id_to_cidrs = {
        pl_id: list(_expanded_prefix_list(context, pl_id)) 
        for pl_id in set(route["PrefixListId"] for route in routes if route.get("PrefixListId"))
    }
    for _i, route in enumerate(routes):
        if route["State"] != "active":
            _debug(f"Ignoring route {_i} in {route_table["__display"]} because its state is \"{route["State"]}\"")
            continue
        cidrs = prefix_list_id_to_cidrs[route["PrefixListId"]] if route.get("PrefixListId") else [route["DestinationCidrBlock"]]
        if len(route.get("TransitGatewayAttachments", [])) > 1:
            _err(f"{route_table["__display"]} has multiple targets for destination {route.get("PrefixListId") or route["DestinationCidrBlock"]}. Script doesn't support that at the moment")
        tgwa = route["TransitGatewayAttachments"][0]
        for cidr in cidrs:
            yield {"destination": cidr, "Type": route["Type"], "State": route["State"], **tgwa}


def build_parser():
    parser = argparse.ArgumentParser(
        description="Tool with 'scan' and 'trace' commands"
    )
    parser.add_argument("-d", "--debug", help="Debug output", action="store_true")

    subparsers = parser.add_subparsers(
        title="commands", dest="command", required=True
    )

    range_parser = subparsers.add_parser(
        "range",
        help="Get IP range of given CIDR",
    )
    range_parser.add_argument("cidr", help="CIDR")
    range_parser.set_defaults(func=cmd_range)

    scan_parser = subparsers.add_parser(
        "scan",
        help="Run a scan of AWS",
    )
    scan_parser.add_argument("-r", "--regions", help="Regions to scan", nargs="*", default=["us-east-1"])
    scan_parser.set_defaults(func=cmd_scan)

    trace_parser = subparsers.add_parser(
        "trace",
        help="Run a trace from one IP to another IP",
    )
    trace_parser.add_argument("source", help="Source IP or CIDR - it must be something in your AWS VPCs!")
    trace_parser.add_argument("target", help="Target IP or CIDR - any IP you want")
    trace_parser.set_defaults(func=cmd_trace)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    global IS_DEBUG
    IS_DEBUG = args.debug
    _debug("Running with debug")
    args.func(args)


if __name__ == "__main__":
    main()
