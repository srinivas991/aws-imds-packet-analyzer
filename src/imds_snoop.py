#!/usr/bin/python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import re
import json
import os

from bcc import BPF
from logging.config import fileConfig

logging.getLogger("bpf").setLevel(logging.ERROR)

#GLOBAL => set logger object as global because initializing the logger in the bpf callback function could cause unnecessary overhead
imds_trace_logger = None

"""Check if a IMDS call is a imdsV1/2 call

:param payload: payload of network call
:type payload: str
:returns: is_v2
:rtype is_v2: bool
"""
def check_v2(payload: str, is_debug=False) -> bool:
    if (is_debug):
        print("========================================================================")
        print("[DEBUG] Payload being checked: ")
        print(payload, end="\n")
        print("========================================================================")

    IMDSV2_TOKEN_PREFIX = "x-aws-ec2-metadata-token"

    # determine if event was imdsv2 call or not
    is_v2 = False
    if IMDSV2_TOKEN_PREFIX in payload.lower():
        is_v2 = True

    return (is_v2)

"""Remove the token from the message 

:param comms: message that need to be redacted.
:type: str
:returns: redacted message
:rtype: str
"""
def hideToken(comms: str) -> str:
    startToken = comms.find("X-aws-ec2-metadata-token: ") + len("X-aws-ec2-metadata-token: ")
    endToken = comms.find("==", startToken) + len("==")

    if (startToken >= len("X-aws-ec2-metadata-token: ")) and (endToken > startToken) :
        newTxt = comms[:startToken] + "**token redacted**" + comms[endToken:]
    else:
        newTxt = comms

    return newTxt


""" get argv info per calling process

:param pid: process id of calling process
:type pid: int
:param proc_name: name of calling process
:type proc_name: str
:returns: proc_info
:rtype proc_info: str
"""
def get_proc_info(pid: int, proc_name: str, is_debug=False) -> str:

    # process IDs start from 1
    if pid == 0:
       return ""

    if (is_debug):
        print("========================================================================")
        print("[DEBUG] pid: " + str(pid))
        print("proc_name: " + proc_info, end="\n")
        print("========================================================================")

    try:
        cmdline = open("/mnt/proc/" + str(pid) + "/cmdline").read()
        proc_info = ":" + proc_name
        proc_info += " argv:" + cmdline.replace('\x00', ' ').rstrip()
        return (proc_info)
    except Exception as e:
        print("Info: ", e)
        error_message = " Unable to get argv information"
        return (error_message)

def get_pod_name(msg: str) -> str:
    pattern = r'[a-z0-9]{64}'
    matches = re.findall(pattern, msg)
    container_id = matches[0] if len(matches) > 0 else "no container id"

    if container_id == "no container id":
    #    imds_trace_logger.info(msg)
       return "-1"
    # /var/lib/docker/containers/{container_id}/config.v2.json|jq -r '.Config.Hostname'
    # print(container_id)

    try:
        with open(f"/mnt/containers/{container_id}/config.v2.json", 'r') as f:
            config_json = json.load(f)
            pod_name = config_json['Config']['Labels']['io.kubernetes.pod.name']
            namespace = config_json['Config']['Labels']['io.kubernetes.pod.namespace']
            return f"{namespace}/{pod_name}"
    except Exception as e:
    #    imds_trace_logger.info(e)
       return "-1"

""" generate output message per imds network call

:param is_v2: flag to represent whether or not the current event is an imdsv1 or imdsv2 event
:type is_v2: bool
:param event: event object returned by C code into per_buffers -> essentially the imds_http_data_t struct in the C code
:type event: bcc.table
:returns: log_msg
:rtype log_msg: str
"""
def gen_log_msg(is_v2: bool, event) -> str:

    log_msg = "IMDSv2 " if is_v2 else "IMDSv1(!) "

    if "IMDSv2" in log_msg:
       return "-1"

    log_msg += get_proc_info(event.pid[0], event.comm.decode())

    if event.parent_comm:
        log_msg += " called by -> " + get_proc_info(event.pid[1], event.parent_comm.decode())
        if event.gparent_comm:
            log_msg += " -> " + get_proc_info(event.pid[2], event.gparent_comm.decode())
            if event.ggparent_comm:
                log_msg += " -> " + get_proc_info(event.pid[3], event.ggparent_comm.decode())

    # log_msg = get_pod_name(log_msg)
    # return hideToken(log_msg)
    return get_pod_name(log_msg)


def print_imds_event(cpu, data, size):
    # let bcc generate the data structure from C declaration automatically given the eBPF event reference (int) -> essentially generates the imds_http_data_t struct in the C code as a bcc.table object
    event = b["imds_events"].event(data)
    """event object
  :attribute pid: stores pids of calling processes in the communication chain (4 pids)
  :type pid: int array[4] (u32 ints)
  :attribute comm: communication process name
  :type comm: bytes (specific encoding unknown)
  :attribute parent_comm: communication process name (parent)
  :type parent_comm: bytes (specific encoding unknown)
  :attribute gparent_comm: communication process name (grand-parent)
  :type gparent_comm: bytes (specific encoding unknown)
  :attribute ggparent_comm: communication process name (great-grand-parent)
  :type parent_comm: bytes (specific encoding unknown)
  :attribute pkt_size: size packet request
  :type pkt_size: int (u32)
  :attribute pkt: the data payload contained in a network request of request
  :type pkt: bytes (specific encoding unknown)
  :attribute contains_payload: flag to indicate if the event has a viable payload to analyze or not
  :type contains_payload: int (u32) 
  """
    #pass whatever data bcc has captured as the event payload to test IMDSv1/2?
    is_v2 = check_v2(event.pkt[:event.pkt_size].decode())
    #generate information string to be logged
    log_msg = gen_log_msg(is_v2, event)

    if log_msg == "-1":
       return

    if(event.contains_payload):
      #log identifiable trace info
      if(is_v2):
        imds_trace_logger.info(log_msg)
        # print('[INFO] ' + log_msg, end="\n")
      else:
        imds_trace_logger.error(log_msg)
        # print('print [WARNING] ' + log_msg, end="\n")
    else:
      #unidentifiable call -> needs further attention -> hence log at error level
      log_msg = "{MISSING PAYLOAD} " + log_msg
      imds_trace_logger.info(log_msg)
    #   print('[ERROR] ' + log_msg, end="\n")


if(__name__ == "__main__"):
  #initialize logger
  logging.config.fileConfig(fname='logging.conf', disable_existing_loggers=False)
  logging.basicConfig(filename=f"/var/log/imds-trace-{os.env.get('HOSTNAME')}.log")
  imds_trace_logger = logging.getLogger("bpf")

  # initialize BPF
  b = BPF('bpf.c')
  # Instruments the kernel function event() using kernel dynamic tracing of the function entry, and attaches our C defined function name() to be called when the kernel function is called.
  b.attach_kprobe(event="sock_sendmsg", fn_name="trace_sock_sendmsg")
  # This operates on a table as defined in BPF via BPF_PERF_OUTPUT() [Defined in C code as imds_events, line 32], and associates the callback Python function to be called when data is available in the perf ring buffer.
  b["imds_events"].open_perf_buffer(print_imds_event)

  # header

  print("Starting ImdsPacketAnalyzer...")
#   print("Currently logging to: " + imds_trace_logger.handlers[0].baseFilename)
#   print("Output format: Info Level:[INFO/ERROR...] IMDS version:[IMDSV1/2?] (pid:[pid]:[process name]:argv:[argv]) -> repeats 3 times for parent process")

  # filter and format output
  while 1:
    # Read messages from kernel pipe
    try:
      # This polls from all open perf ring buffers, calling the callback function that was provided when calling open_perf_buffer for each entry.
      b.perf_buffer_poll()
    except ValueError:
      # Ignore messages from other tracers
      print("ValueError here")
      continue
    except KeyboardInterrupt:
      exit()
