#!/usr/bin/env python3

"""
During the process of creating stack and resource extract, it simplify the code a lot to have NULL value.
The NULL indicate a value to remove, but you don't have to have a complex code around that to do.
"""
from pprint import pprint

from aws_stack_diff.utils import walk_json


class NullSingleton(object):
    def __str__(self):
        return '<NULL object singleton>'


NULL = NullSingleton()  # have same id


def clean_null(input_json):
    """
    @:param json The json object to clean
    """

    # def walk_json(e, dict_fct=i, list_fct=i, num_fct=i, str_fct=i, bool_fct=i, null_fct=i):
    def dict_proc(d):
        return {k: v for k, v in d.items() if v is not NULL and k is not NULL}

    def list_proc(l):
        return [e for e in l if e is not NULL]

    def not_found(e):
        return e

    res = walk_json(input_json, dict_fct=dict_proc, list_fct=list_proc, not_found=not_found)
    return res
