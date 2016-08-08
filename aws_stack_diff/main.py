#!/usr/bin/env python2.7
from __future__ import unicode_literals, print_function

import argparse
import base64
import json
import random
import sys

import datadiff
import six
from aws_stack_diff import stack2res
from aws_stack_diff import stackres2res
from aws_stack_diff.utils import walk_json, base64_decode
from boto3_wrapper.boto_session import SessionWrapper as BotoSession


def list_stacks(boto_session):
    response = boto_session.cf.describe_stacks()
    return sorted(s['StackName'] for s in response)


def everything_to_string(j):
    def bool_fct(b):
        print('gotten boolean', b)
        return str(b).lower()

    def num_fct(n):
        return str(n)

    return walk_json(j, num_fct=num_fct, bool_fct=bool_fct)


def better_userdata(j):
    def dict_fct(d):
        if 'UserData' in d and isinstance(d['UserData'], six.string_types):
            d['UserData'] = {"Fn::Base64": base64_decode(d['UserData'])}
        return d

    return walk_json(j, dict_fct=dict_fct)


def get_both(boto_session, stack_name):
    """
    For a stack name, return both stack and resources, ready to compare
    """

    stack_res = stack2res.stack2res(boto_session, stack_name)
    ressources_res = stackres2res.stackres2res(boto_session, stack_name, stack_res)

    stack_res_cleaned = better_userdata(everything_to_string(stack_res))
    ressources_res_cleaned = better_userdata(everything_to_string(ressources_res))

    return stack_res_cleaned, ressources_res_cleaned


def to_json(obj):
    return json.dumps(obj, indent=2, sort_keys=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Show the diff between a stack and it's resources")
    parser.add_argument('-p', '--aws-profile', default='default',
                        help='The aws profile name (use the default one if not found)')
    parser.add_argument('stack_name', nargs='?', default=None,
                        help='specify a stack name, by default print the stack names'
                             ', if the name is "all" print only if the stack if different for each stacks')

    args = parser.parse_args()

    boto_session = BotoSession(profile_name=args.aws_profile)

    if not args.stack_name:
        print('Stacks : ')
        for stack in list_stacks(boto_session):
            print('- %s' % stack)
        sys.exit(0)

    stack_name = args.stack_name

    if stack_name.lower() == 'all':
        # We shoudn't have a stack named all, so we use it as keyword
        for cur_stack_name in list_stacks(boto_session):
            stack_res, ressources_res = get_both(boto_session, cur_stack_name)
            if stack_res != ressources_res:
                print('- != %s' % cur_stack_name)
            else:
                print('- good %s' % cur_stack_name)
        sys.exit()

    nb_diff = 0

    stack_res, ressources_res = get_both(boto_session, stack_name)

    stack_keys = set(stack_res.keys())
    ressources_keys = set(ressources_res.keys())

    # We need the stack resources id on the output, because the comparison don't have that info
    r = boto_session.cf.describe_stack_resources(StackName=stack_name)
    log2ph_id = {r['LogicalResourceId']: r.get('PhysicalResourceId') for r in r}

    if stack_keys != ressources_keys:
        print('!!! Keys are differents : ')
        nb_diff += 1
        print(datadiff.diff(sorted(stack_keys), sorted(ressources_keys)))

    for key in stack_keys & ressources_keys:
        s, r = stack_res[key], ressources_res[key]
        if s == r:
            continue
        print('!!! Different element : %s (%s)' % (key, log2ph_id.get(key, 'not_found')))
        nb_diff += 1
        print(datadiff.diff(to_json(s), to_json(r)))

    if nb_diff == 0:
        txt = [
            "Everything's the same.",
            'No difference, congrat.',
            "You're the best, nothing changed",
            "Is it me or the resources are similar to the stack ?",
        ]
        print(random.choice(txt))
        sys.exit(0)
    else:
        print('%s elements changed !' % nb_diff)
        sys.exit(1)
