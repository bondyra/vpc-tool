#!/usr/bin/env python3
import argparse
import sys
import ipaddress
from contextlib import ExitStack
from concurrent.futures import ThreadPoolExecutor, as_completed

import boto3
import json


def cmd_range(args):
    try:
        n = ipaddress.ip_network(args.cidr, strict=False)
        print(f"{n[0]} - {n[-1]} ({n.num_addresses} IPs)")
    except Exception as e:
        print(f"Something went wrong: {e}")


def cmd_ip_to_cidr(args):
    try:
        ip = ipaddress.IPv4Address(args.ip)
        for prefix in range(24, 16 - 1, -1):
            network = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
            print(str(network))
    except Exception as e:
        print(f"Something went wrong: {e}")


_default_session = boto3.Session()
_provider_cache = {}


def _get_cached_client(profile, region, client_name):
    key = (profile, region, client_name)

    if key not in _provider_cache:
        session = boto3.Session(profile_name=profile, region_name=region)
        _provider_cache[key] = session.client(client_name)

    return _provider_cache[key]


def _aws_call(profile, region, client_name, method_name, response_field, id_field, paginated, stupidly_paginated=False):
    client = _get_cached_client(profile, region, client_name)
    if paginated:
        paginator = client.get_paginator(method_name)
        for page in paginator.paginate():
            for r in page.get(response_field):
                yield {"__id": r.get(id_field), **r}
    elif stupidly_paginated:
        next_token = None
        while True:
            kwargs = {"MaxResults": 100}
            if next_token is not None:
                kwargs["NextToken"] = next_token
            response = client.describe_prefix_lists(**kwargs)
            for r in response.get(response_field):
                yield {"__id": r.get(id_field), **r}
            next_token = response.get("NextToken")
            if not next_token:
                break
    else:
        response = getattr(client, method_name)()
        for r in response.get(response_field):
            yield {"__id": r.get(id_field), **r}


funcs = {
    "vpcs": lambda profile, region: _aws_call(profile, region, "ec2", "describe_vpcs", "Vpcs", "VpcId", False),
    "subnets": lambda profile, region: _aws_call(profile, region, "ec2", "describe_subnets", "Subnets", "SubnetId", False),
    "route_tables": lambda profile, region: _aws_call(profile, region, "ec2", "describe_route_tables", "RouteTables", "RouteTableId", True),
    "internet_gateways": lambda profile, region: _aws_call(profile, region, "ec2", "describe_internet_gateways", "InternetGateways", "InternetGatewayId", False),
    "nat_gateways": lambda profile, region: _aws_call(profile, region, "ec2", "describe_nat_gateways", "NatGateways", "NatGatewayId", True),
    "prefix_lists": lambda profile, region: _aws_call(profile, region, "ec2", "describe_prefix_lists", "PrefixLists", "PrefixListId", False, True),
    "vpc_endpoints": lambda profile, region: _aws_call(profile, region, "ec2", "describe_vpc_endpoints", "VpcEndpoints", "VpcEndpointId", False, True),
    "vpc_peerings": lambda profile, region: _aws_call(profile, region, "ec2", "describe_vpc_peering_connections", "VpcPeeringConnections", "VpcPeeringConnectionId", False),
    "virtual_gateways": lambda profile, region: _aws_call(profile, region, "ec2", "describe_virtual_gateways", "virtualGateways", "virtualGatewayId", False)
}
# TODO: tgw


def _aws_all(regions, max_workers=20):
    profiles = _default_session.available_profiles

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for name, func in funcs:
            for profile in profiles:
                for region in regions:
                    future = executor.submit(func, profile, region)
                    futures[future] = (profile, region, name)

        for future in as_completed(futures):
            profile, region, name = futures[future]
            try:
                result = future.result()
            except Exception:
                pass
            for r in result:
                yield {"__func": name,"__profile": profile, "__region": region, **r}


def is_valid_ipv4_or_cidr(value):
    try:
        ipaddress.ip_address(value)
        return True
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def validate_trace_params(param1, param2):
    return is_valid_ipv4_or_cidr()


def cmd_scan(args):
    results = _aws_all([])
    with ExitStack() as stack:
        files = {f"{name}.cache": stack.enter_context(open(name, "w")) for name in funcs}
        for r in results:
            files[r["__func"]].write(json.dumps(r))
            files[r["__func"]].write("\n")


def _load_context():
    try:
        context = {}
        for name in funcs:
            with open(f"{name}.cache", "r") as f:
                context[name] = [json.loads(l) for l in f.readlines()]
        return context
    except:
        print("Run scan command first.")
        exit(1)


def next_hop(source, target, context):
    # check to which subnet this source belongs to
    # check its route table
    # check which entry is most specific
    # check destination of that entry
    # if that entry is transit gateway, TODO kurwa nie wiem
    pass


def cmd_trace(args):
    try:
        validate_trace_params(args.source, args.target)
    except ValueError as e:
        print(f"Validation error: {e}", file=sys.stderr)
        sys.exit(1)
    context = _load_context()
    source = args.source
    while True:
        source = next_hop(source, args.target, context)
        if source == None:
            break


def build_parser():
    parser = argparse.ArgumentParser(
        description="Tool with 'scan' and 'trace' commands"
    )

    subparsers = parser.add_subparsers(
        title="commands", dest="command", required=True
    )

    range_parser = subparsers.add_parser(
        "range",
        help="sasddassdwwdqdwqwdq",
    )
    range_parser.add_argument("cidr", help="CIDR")
    range_parser.set_defaults(func=cmd_range)

    ip_to_cidr_parser = subparsers.add_parser(
        "ip-to-cidr",
        help="sasddassdwwdqdwqwdq",
    )
    ip_to_cidr_parser.add_argument("ip", help="IP")
    ip_to_cidr_parser.set_defaults(func=cmd_ip_to_cidr)

    scan_parser = subparsers.add_parser(
        "scan",
        help="Run a scan of AWS",
    )
    scan_parser.set_defaults(func=cmd_scan)

    trace_parser = subparsers.add_parser(
        "trace",
        help="Run a trace from one IP to another IP",
    )
    trace_parser.add_argument("source", help="Source IP or CIDR")
    trace_parser.add_argument("target", help="Target IP or CIDR")
    trace_parser.set_defaults(func=cmd_trace)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
