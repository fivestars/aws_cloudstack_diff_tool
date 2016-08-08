#!/usr/bin/env python3
from __future__ import unicode_literals, print_function

import base64
import collections
import json
import numbers

import six


def i(e):  # identity
    return e


def sorted_dict(input_dict):
    return sorted(list(input_dict), key=lambda d: json.dumps(d, sort_keys=True))


def not_found_default(e):
    raise Exception('Type of %s not found' % repr(e))


def walk_json(e, dict_fct=i, list_fct=i, num_fct=i, str_fct=i, bool_fct=i, null_fct=i, not_found=not_found_default):
    """
    Go throught a json and call each function accordingly of the element type
    for each element, the value returned is used for the json output
    This doesn't change the input json, but re-create a new json object.
    (calling it without any function return a copy of a json for example)
    The calling is deep-first.
    ex : ['a', {'b':3}] will call :
        - str_fct('a')
        - num_fct(3)
        - dict_fct({'b':3})
        - list_fct(['a', {'b':3}])
    and if every function is set to return None
    ex : ['a', {'b':3}] will call :
        - str_fct('a')
        - num_fct(3)
        - dict_fct({'b':None})
        - list_fct([None, None])
    :param e:
    :param dict_fct:
    :param list_fct:
    :param num_fct:
    :param str_fct:
    :param bool_fct:
    :param null_fct:
    :param not_found:
    :return:
    """
    if e is None:
        return null_fct(e)
    if isinstance(e, six.string_types):
        return str_fct(e)
    if isinstance(e, numbers.Number):
        return num_fct(e)
    if isinstance(e, bool):
        return bool_fct(e)

    param = {  # only create it when needed
        'dict_fct': dict_fct, 'list_fct': list_fct, 'num_fct': num_fct,
        'str_fct': str_fct, 'bool_fct': bool_fct, 'null_fct': num_fct,
        'not_found': not_found,
    }

    if isinstance(e, collections.Mapping):
        return dict_fct({k: walk_json(v, **param) for k, v in e.items()})
    if isinstance(e, collections.Iterable):
        return list_fct([walk_json(v, **param) for v in e])
    return not_found(e)


# Used for the json_default as "every element under this one"

def json_default(j, value, *path):
    """
    Put a default in place of a json
    :param j: the json value
    :param value: the value to set as default
    :param path: the path leading to the value
    """
    head, rest = path[0], path[1:]
    is_star = head == '*'
    if not rest:
        if not is_star:
            j[head] = j.get(head, value)
        else:
            assert False  # how to manage that one ?
    else:
        if not is_star:
            json_default(j[head], value, *rest)
        else:
            # works for list now
            for e in j:
                json_default(e, value, *rest)


# def base64_decode(input_str):
#     return base64.encodebytes(input_str.encode('UTF-8')).decode('UTF-8')

def base64_decode(input_str):
    return base64.decodebytes(input_str.encode('UTF-8')).decode('UTF-8')
