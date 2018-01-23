#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import json
import os
import tarfile
import tempfile


def extract_tar_file(filename, tempdirectory):
    """
    extracts tar file
    :param filename:
    :param tempdirectory:
    :return:
    """
    tar = tarfile.open(filename)
    tar.extractall(tempdirectory)
    tar.close()


def get_files_in_directory(path, filter=['.json', '.tar.gz']):
    """
    lists all files in a directory (path) with extension specified by filter
    :param path:
    :param filter:
    :return: list with matched filenames
    """
    file_list = list()
    for root, dirs, files in os.walk(path):
        for f in files:
            if any([True for fi in filter if fi.endswith(f.split(".")[-1])]):
                file_list.append(os.path.abspath(os.path.join(root, f)))
    return file_list


def parse_objects_in_files(files):
    """
    parses all files with specified suffixes and extracts the specified attributes
    :param files:
    :return: list with data objects
    """
    interesting_files = {"35____add-host__": dict(o_attr=["ipv4-address"], o_type="hosts"),
                         "36____add-group__": dict(o_attr=["members"], o_type="groups"),
                         "27____add-network__": dict(o_attr=["mask-length4", "subnet4"], o_type="networks"),
                         "28____add-service-group__": dict(o_attr=["members"], o_type="service_groups"),
                         "10____add-service-tcp__": dict(o_attr=["port"], o_type="services_tcp"),
                         "05____add-service-udp__": dict(o_attr=["port"], o_type="services_udp"),
                         "38____add-address-range__": dict(o_attr=["ipv4-address-first", "ipv4-address-last"],
                                                           o_type="address_ranges")
                         }

    data_objects = dict()
    for entry in interesting_files.values():
        data_objects[entry["o_type"]] = dict()

    # check matching files
    for file in files:
        for fi in interesting_files.keys():
            if fi in file:
                data_for_file = interesting_files[fi]
                # parse objects
                data_objects[data_for_file["o_type"]] = parse_object(file, data_for_file["o_attr"])

    return data_objects


def parse_object(filename, attributes):
    """
    parse objects
    :param filename:
    :param attributes:
    :return: dict with objects name as key
    """
    o_attr = dict()
    with open(filename) as fp:
        json_data = json.load(fp)
        for entry in json_data:
            if "name" not in entry:
                entry["name"] = "undefined"
            for entry_attribute in entry:
                for a in attributes:
                    if entry_attribute.startswith(a):
                        if entry["name"] not in o_attr:
                            o_attr[entry["name"]] = dict()
                        o_attr[entry["name"]][entry_attribute] = entry[entry_attribute]
                        continue
                    if a == entry_attribute:
                        if len(attributes) > 1:
                            if entry["name"] not in o_attr:
                                o_attr[entry["name"]] = dict()
                            o_attr[entry["name"]][entry_attribute] = entry[a]
                        else:
                            o_attr[entry["name"]] = entry[a]
                        continue

    return o_attr


def parse_rulebases(files, objects):
    nat_rulebase = list()
    access_rulebase = list()

    for file in files:
        if "01____add-access-rule_" in file:
            with open(file) as fp:
                json_data = json.load(fp)
                for rule in json_data:
                    if "name" not in rule:
                        rule["name"] = "undefined"
                    r = AccessRule(rule["name"], rule["position"], rule["enabled"], rule["action"],
                                   rule["comments"])
                    if rule["source-negate"]:
                        r._negate_source = True
                    if rule["destination-negate"]:
                        r._negate_destination = True
                    if rule["service-negate"]:
                        r._negate_service = True
                    r._sourcelist = get_multi_values_for_attribute(rule, "source.", objects)
                    r._destinationlist = get_multi_values_for_attribute(rule, "destination.", objects)
                    r._servicelist = get_multi_values_for_attribute(rule, "service.", objects)
                    #                        print(rule)
                    access_rulebase.append(r)
        if "01____add-nat-rule_" in file:
            with open(file) as fp:
                json_data = json.load(fp)
                for rule in json_data:
                    r = NATRule(rule["position"], rule["enabled"], rule["comments"])
                    r._source_org = get_multi_values_for_attribute(rule, "original-source", objects)[0]
                    r._destination_org = get_multi_values_for_attribute(rule, "original-destination", objects)[0]
                    r._service_org = get_multi_values_for_attribute(rule, "original-service", objects)[0]
                    r._source_tran = get_multi_values_for_attribute(rule, "translated-source", objects)[0]
                    r._destination_tran = get_multi_values_for_attribute(rule, "translated-destination", objects)[0]
                    r._service_tran = get_multi_values_for_attribute(rule, "translated-service", objects)[0]
                    nat_rulebase.append(r)

    return nat_rulebase, access_rulebase


def get_multi_values_for_attribute(rule, attribute, objects):
    """
    parse objects with multiple values for a certain attribute, e.g. member.0, member.1
    :param rule:
    :param attribute:
    :param objects:
    :return:
    """
    result = list()
    for attr in rule:
        if attr.startswith(attribute):
            name = resolve_objects(rule[attr], objects)
            if name != rule[attr] or name == "Any":  # mapping found
                result.append(name)
            else:  # mapping not found, probably group
                olist = resolve_object_groups(rule[attr], objects)
                if len(olist) == 0:
                    result.append(name)
                else:
                    for item in olist:
                        result.append(item)
    return result


def resolve_objects(name, objects):
    """
    resolve objects, try to find network/address/range/... for a name
    :param name:
    :param objects:
    :return:
    """
    if name == "Any":
        return "Any"
    for types in ["networks", "address_ranges", "hosts", "services_tcp", "services_udp"]:
        for item in objects[types]:
            if name == item:
                if types == "networks" and "subnet4" in objects[types][item] and "mask-length4" in objects[types][item]:
                    return "%s/%s" % (objects[types][item]["subnet4"], objects[types][item]["mask-length4"])
                if types == "address_ranges" and "ipv4-address-first" in objects[types][item] and "ipv4-address-last" in \
                        objects[types][item]:
                    return "%s-%s" % (
                        objects[types][item]["ipv4-address-first"], objects[types][item]["ipv4-address-last"])
                if types == "services_tcp" and "port" in objects[types][item]:
                    return "tcp/%s" % (objects[types][item]["port"])
                if types == "services_udp" and "port" in objects[types][item]:
                    return "udp/%s" % (objects[types][item]["port"])
                if types == "hosts" and "ipv4-address" in objects[types][item]:
                    return "%s" % (objects[types][item]["ipv4-address"])
                return objects[types][item]
    return name


def resolve_object_groups(name, objects):
    """
    resolve object groups
    TODO: nested groups are not handled yet
    :param name:
    :param objects:
    :return:
    """
    result = list()
    for types in ["groups", "service_groups"]:
        for item in objects[types]:
            if name == item:
                for member in objects[types][item]:
                    result.append(resolve_objects(objects[types][item][member], objects))
                return result
    return result


class AccessRule(object):
    """
    represents an access rule
    """
    _sourcelist = list()
    _destinationlist = list()
    _servicelist = list()

    def __init__(self, name, position, enabled, action, comments):
        self._name = name
        self._position = position
        self._enabled = enabled
        self._action = action
        self._comments = comments
        self._negate_source = False
        self._negate_destination = False
        self._negate_service = False

    def map(self):
        mapped = list()
        for src in self._sourcelist:
            for dst in self._destinationlist:
                for srv in self._servicelist:
                    nsrc = src if not self._negate_source else "!%s" % (src)
                    ndst = dst if not self._negate_destination else "!%s" % (dst)
                    nsrv = srv if not self._negate_service else "!%s" % (srv)

                    mapped.append("%s|%s|%s|%s|%s|%s|%s" % (
                        self._position, self._enabled, self._name, nsrc, ndst, nsrv, self._action))
        #                    mapped.append("%s|%s|%s|%s|%s|%s|%s|%s" % (
        #                    self._position, self._enabled, self._name, src, dst, srv, self._comments.replace("\n","-"), self._action))
        if len(mapped) == 0:
            mapped.append("UNDEFINED - missing source/destination/service")
        return mapped

    def __str__(self):
        return "\n".join(self.map())


class NATRule(object):
    """
    represents a NAT rule
    """
    _source_org = ""
    _destination_org = ""
    _service_org = ""
    _source_tran = ""
    _destination_tran = ""
    _service_tran = ""

    def __init__(self, position, enabled, comments):
        self._position = position
        self._enabled = enabled
        self._comments = comments

    def __str__(self):
        src_org = "0.0.0.0" if self._source_org == "Any" else self._source_org
        dst_org = "0.0.0.0" if self._destination_org == "Any" else self._destination_org
        srv_orig = "0-65535" if self._service_org == "Any" else self._service_org
        src_trans = src_org if self._source_tran == "Original" else self._source_tran
        dst_trans = dst_org if self._destination_tran == "Original" else self._destination_tran
        srv_trans = srv_orig if self._service_tran == "Original" else self._service_tran
        return "%s|%s|%s|%s|%s|%s|%s|%s" % (
            self._position, self._enabled, src_org, dst_org, srv_orig, src_trans,
            dst_trans, srv_trans)


### MAIN ###
if __name__ == "__main__":
    # CLI parser
    parser = argparse.ArgumentParser(description='Check Point Policy Export Resolver')
    parser.add_argument('-v', '--verbose', help='Verbose', action='store_true')
    parser.add_argument('-n', '--nat', help='Show NAT Rulebase', action='store_true', default=True)
    parser.add_argument('-a', '--access', help='Show Access Rulebase', action='store_true')
    parser.add_argument('-p', '--policyexport', help='Policy Export Package, e.g. policyexport.tar.gz', required=True)

    args = parser.parse_args()

    if not args.nat and not args.access:
        parser.error('Either --nat or --access required')

    tempdirectory = tempfile.TemporaryDirectory().name

    # verbose output
    if args.verbose:
        print(tempdirectory)

    # extract files to temp dir
    extract_tar_file(args.policyexport, tempdirectory)

    # get all tar.gz -files (e.g. access policy, nat policy)
    files_tgz = get_files_in_directory(tempdirectory, filter=['.tar.gz'])

    # extract them
    for f in files_tgz:
        extract_tar_file(f, tempdirectory)

    # get all json files
    files_json = get_files_in_directory(tempdirectory, filter=['.json'])

    # verbose output
    if args.verbose:
        print(files_json)

    # get all objects
    objects = parse_objects_in_files(files_json)

    # get nat/access rulebase
    nat_rulebase, access_rulebase = parse_rulebases(files_json, objects)

    # show access rulebase
    if args.access:
        for item in access_rulebase:
            print(item)

    # show nat rulebase
    if args.nat:
        for item in nat_rulebase:
            print(item)
