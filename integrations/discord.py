# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.


#/usr/bin/env python3

import json
import os
import sys

# Exit error codes
ERR_NO_REQUEST_MODULE   = 1
ERR_BAD_ARGUMENTS       = 2
ERR_FILE_NOT_FOUND      = 6
ERR_INVALID_JSON        = 7

try:
    import requests
    from requests.auth import HTTPBasicAuth
except Exception as e:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(ERR_NO_REQUEST_MODULE)


# ossec.conf configuration structure
# <integration>
#     <name>custom-discord</name>
#     <hook_url>https://discord.com/api/webhooks/XXXXXXXXXXX</hook_url>
#     <alert_format>json</alert_format>
# </integration>


# Global vars
debug_enabled   = False
pwd             = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert      = {}
json_options    = {}

# Log path
LOG_FILE        = f"{pwd}/logs/integrations.log"

# Constants
ALERT_INDEX     = 1
WEBHOOK_INDEX   = 3


def main(args):
    global debug_enabled
    try:
        # Read arguments
        bad_arguments: bool = False
        if len(args) >= 4:
            msg = f"{args[1]} {args[2]} {args[3]} {args[4] if len(args) > 4 else ''} {args[5] if len(args) > 5 else ''}"
            debug_enabled = (len(args) > 4 and args[4] == "debug)
        else:
            msg = "# ERROR: Wrong arguments"
            bad_arguments = True

        # Logging the call
        with open(LOG_FILE, "a") as f:
            f.write(msg + '\n')

        if bad_arguments:
            debug(f"# ERROR: Exiting, bad arguments. Inputted: {args}" )
            sys.exit(ERR_BAD_ARGUMENTS)

        # Core function
        process_args(args)

    except Exception as e:
        debug(str(e))
        raise

def process_args(args) -> None:
    """
        This is the core function, creates a message with all valid fields
        and overwrite or add with the optional fields

        Parameters
        ----------
        args : list[str]
            The argument list from main call
    """
    debug("# Running Discord script")

    # Read args
    alert_file_location: str     = args[ALERT_INDEX]
    webhook: str                 = args[WEBHOOK_INDEX]
    options_file_location: str   = ''

    # Look for options file location
    for idx in range(4, len(args)):
        if(args[idx][-7:] == "options"):
            options_file_location = args[idx]
            break

    # Load options. Parse JSON object.
    json_options = get_json_options(options_file_location)
    debug(f"# Opening options file at '{options_file_location}' with '{json_options}'")

    # Load alert. Parse JSON object.
    json_alert  = get_json_alert(alert_file_location)
    debug(f"# Opening alert file at '{alert_file_location}' with '{json_alert}'")

    debug("# Generating message")
    msg: any = generate_msg(json_alert, json_options)

    if not len(msg):
        debug("# ERROR: Empty message")
        raise Exception

    debug(f"# Sending message {msg} to Discord server")
    send_msg(msg, webhook)


def debug(msg: str) -> None:
    """
        Log the message in the log file with the timestamp, if debug flag
        is enabled

        Parameters
        ----------
        msg : str
            The message to be logged.
    """
    if debug_enabled:
        print(msg)
        with open(LOG_FILE, "a") as f:
            f.write(msg + '\n')

def generate_msg(alert: any, options: any) -> any:
    """
        Generate the JSON object with the message to be send

        Parameters
        ----------
        alert : any
            JSON alert object.
        options: any
            JSON options object.

        Returns
        -------
        msg: str
            The JSON message to send
    """
    level           = alert['rule']['level']

    # colors from https://gist.github.com/thomasbnt/b6f455e2c7d743b796917fa3c205f812
    if(alert_level < 5):
        # green
        color = "5763719"
    elif(alert_level >= 5 and alert_level <= 7):
        # yellow
        color = "16705372"
    else:
        # red
        color = "15548997"
        
    msg             = {}
    msg['color']    = color
    msg['pretext']  = "WAZUH Alert"
    msg['title']    = alert['rule']['description'] if 'description' in alert['rule'] else "N/A"
    msg['text']     = alert.get('full_log')

    msg['fields']   = []
    if 'agent' in alert:
        msg['fields'].append({
            "title": "Agent",
            "value": "({0}) - {1}".format(
                alert['agent']['id'],
                alert['agent']['name']
            ),
        })
    if 'agentless' in alert:
        msg['fields'].append({
            "title": "Agentless Host",
            "value": alert['agentless']['host'],
        })
    msg['fields'].append({"title": "Location", "value": alert['location']})
    msg['fields'].append({
        "title": "Rule ID",
        "value": "{0} _(Level {1})_".format(alert['rule']['id'], level),
    })

    msg['ts']       = alert['id']

    if(options):
        msg.update(options)

    attach = {'attachments': [msg]}

    return json.dumps(attach)

# read configuration
alert_file = sys.argv[1]
user = sys.argv[2].split(":")[0]
hook_url = sys.argv[3]

# read alert file
with open(alert_file) as f:
    alert_json = json.loads(f.read())

# extract alert fields
alert_level = alert_json["rule"]["level"]

# colors from https://gist.github.com/thomasbnt/b6f455e2c7d743b796917fa3c205f812
if(alert_level < 5):
    # green
    color = "5763719"
elif(alert_level >= 5 and alert_level <= 7):
    # yellow
    color = "16705372"
else:
    # red
    color = "15548997"

# agent details
if "agentless" in alert_json:
	  agent_ = "agentless"
else:
    agent_ = alert_json["agent"]["name"]

# combine message details
payload = json.dumps({
    "content": "",
    "embeds": [
        {
		    "title": f"Wazuh Alert - Rule {alert_json['rule']['id']}",
				"color": color,
				"description": alert_json["rule"]["description"],
				"fields": [{
                        # TODO: each field item is a subheadline + content following it 
                        # -> turn this into a dictionary/tuple/frozenset? and read each one in a for loop?
						"name": "Agent",
						"value": agent_,
						"inline": True
						}]
        }
    ]
})

# send message to discord

def send_msg(msg: str, url: str) -> None:
    """
        Send the message to the API

        Parameters
        ----------
        msg : str
            JSON message.
        url: str
            URL of the API.
    """
    headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
    res     = requests.post(url, data=msg, headers=headers)
    debug(f"# Response received: {res.json}")
