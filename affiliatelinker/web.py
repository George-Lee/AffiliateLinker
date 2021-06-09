import hashlib
import hmac
import json
import logging
import os
import re
import time

import requests
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from requests_auth_aws_sigv4 import AWSSigV4

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

DISCORD_APP_PUBLIC_KEY = os.getenv("DISCORD_APP_PUBLIC_KEY")
PAAPI_ACCESS_KEY = os.getenv("PAAPI_ACCESS_KEY")
PAAPI_SECRET_KEY = os.getenv("PAAPI_SECRET_KEY")
PAAPI_PARTNER_TAG = os.getenv("PAAPI_PARTNER_TAG")
PAAPI_REGION = os.getenv("PAAPI_REGION")

logger.debug(PAAPI_PARTNER_TAG)
logger.debug(DISCORD_APP_PUBLIC_KEY)

INTERACTION_TYPE_PING = 1
INTERACTION_TYPE_APPLICATION_COMMAND = 2

INTERACTION_RESPONSE_TYPE_PONG = 1
INTERACTION_RESPONSE_TYPE_CHANNEL_MESSAGE_WITH_SOURCE = 4
INTERACTION_APPLICATION_COMMAND_CALLBACK_FLAG_EPHEMERAL = 64

verify_key = VerifyKey(bytes.fromhex(DISCORD_APP_PUBLIC_KEY))
logger.debug(verify_key)


def jsonify(body, status_code=200, headers=None):
    if headers is None:
        headers = {}

    return {"statusCode": status_code, "headers": headers, "body": json.dumps(body)}


def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def get_signature_key(key, date_stamp, region_name, service_name):
    k_date = sign(f"AWS4{key}".encode("utf-8"), date_stamp)
    k_region = sign(k_date, region_name)
    k_service = sign(k_region, service_name)
    return sign(k_service, "aws4_request")


def handler(event, context):
    for header in list(event["headers"]):
        event["headers"][header.lower()] = event["headers"][header]

    try:
        timestamp = int(event["headers"].get("x-signature-timestamp", "0"))
        if abs(time.time() - timestamp) > 2:
            return jsonify({"error": "Invalid timestamp."}, status_code=401)
    except ValueError:
        return jsonify({"error": "Invalid timestamp."}, status_code=401)

    try:
        verify_key.verify(
            "{}{}".format(timestamp, event["body"]).encode(),
            bytes.fromhex(event["headers"].get("x-signature-ed25519", "")),
        )
    except BadSignatureError:
        return jsonify({"error": "Invalid request signature."}, status_code=401)

    if event["headers"]["content-type"] != "application/json":
        return jsonify({"error": "Invalid Content-Type."}, status_code=400)

    body = json.loads(event["body"])

    if event["path"] == "/" and event["httpMethod"] == "POST":
        if body["type"] == INTERACTION_TYPE_PING:
            return jsonify({"type": INTERACTION_RESPONSE_TYPE_PONG})

        if body["type"] == INTERACTION_TYPE_APPLICATION_COMMAND:
            options = {}
            for option in body["data"].get("options", []):
                options[option["name"]] = option["value"]

            if "item" not in options:
                return jsonify(
                    {
                        "type": INTERACTION_RESPONSE_TYPE_CHANNEL_MESSAGE_WITH_SOURCE,
                        "data": {
                            "content": "Invalid options.",
                            "flags": INTERACTION_APPLICATION_COMMAND_CALLBACK_FLAG_EPHEMERAL,
                        },
                    }
                )

            asin = options.get("item", "Not-an-asin").strip()
            logger.debug(asin)
            asin_pattern = "([A-Z0-9]{10})"

            if asinl := re.findall(asin_pattern, asin):
                asin = asinl[0]
            else:
                logger.debug(repr(asin))
                return jsonify(
                    {
                        "type": INTERACTION_RESPONSE_TYPE_CHANNEL_MESSAGE_WITH_SOURCE,
                        "data": {
                            "content": "Invalid options.",
                            "flags": INTERACTION_APPLICATION_COMMAND_CALLBACK_FLAG_EPHEMERAL,
                        },
                    }
                )

            if "channel_id" not in body:
                return jsonify(
                    {
                        "type": INTERACTION_RESPONSE_TYPE_CHANNEL_MESSAGE_WITH_SOURCE,
                        "data": {
                            "content": "You're not in a channel.",
                            "flags": INTERACTION_APPLICATION_COMMAND_CALLBACK_FLAG_EPHEMERAL,
                        },
                    }
                )

            aws_auth = AWSSigV4(
                "ProductAdvertisingAPI",
                region=PAAPI_REGION,
                aws_access_key_id=PAAPI_ACCESS_KEY,
                aws_secret_access_key=PAAPI_SECRET_KEY,
            )
            headers = {
                "content-type": "application/json; charset=UTF-8",
                "content-encoding": "amz-1.0",
                "x-amz-target": "com.amazon.paapi5.v1.ProductAdvertisingAPIv1.GetItems",
            }

            request_data = {
                "ItemIds": [asin],
                "PartnerTag": PAAPI_PARTNER_TAG,
                "PartnerType": "Associates",
            }
            r = requests.post(
                "https://webservices.amazon.co.uk/paapi5/getitems",
                data=json.dumps(request_data),
                auth=aws_auth,
                headers=headers,
            )

            referral_link = r.json()["ItemsResult"]["Items"][0]["DetailPageURL"]

            return jsonify(
                {
                    "type": INTERACTION_RESPONSE_TYPE_CHANNEL_MESSAGE_WITH_SOURCE,
                    "data": {
                        "content": f"Affiliate link for {options.get('item')}:\n{referral_link}",
                    },
                }
            )
