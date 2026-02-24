#!/bin/bash

sudo cat /proc/kallsyms | grep -i "sys_call_table"
