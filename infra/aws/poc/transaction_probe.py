"""Disposable Lambda/DynamoDB primitive probe, not a custody store adapter.

The synthetic counter/intent/outbox transaction tests AWS concurrency and durable
idempotency primitives only. It does not authorize requests, implement custody
state rules, disclose results, access a corpus, export a ledger, or sign anything.
Invoke through IAM only; no function URL. PROBE_TABLE names one disposable table.
The execution role has access to that table only and has no logging permission.
"""
import hashlib
import json
import os
import re
import uuid


def probe(client, table, event):
    if (not isinstance(event, dict) or set(event) != {"id", "binding"}
            or not isinstance(event["id"], str)
            or not re.fullmatch(r"synthetic-[0-9]{1,3}", event["id"])
            or event["binding"] not in ("valid", "conflicting")):
        return {"code": "INPUT_REFUSED"}
    key = event["id"]
    binding = hashlib.sha256(event["binding"].encode()).hexdigest()
    # Separate from diagnostic fixtures; never reset an exhausted counter.
    prefix = "synthetic-race:"
    expected = {"pk": {"S": prefix + "intent:" + key}, "binding": {"S": binding}}

    def existing():
        return client.get_item(TableName=table, Key={"pk": {"S": prefix + "intent:" + key}},
                               ConsistentRead=True).get("Item")

    try:
        item = existing()
        if item:
            return {"code": "REPLAY" if item == expected else "BINDING_CONFLICT"}
        client.transact_write_items(
            # Different service token on every invocation: the durable intent
            # condition, not DynamoDB's short token window, prevents recharging.
            ClientRequestToken=uuid.uuid4().hex,
            TransactItems=[
                {"Update": {
                    "TableName": table, "Key": {"pk": {"S": prefix + "counter"}},
                    "UpdateExpression": "SET remaining = remaining - :one, held = held + :one",
                    "ConditionExpression": "remaining >= :one",
                    "ExpressionAttributeValues": {":one": {"N": "1"}},
                }},
                {"Put": {"TableName": table, "Item": expected,
                         "ConditionExpression": "attribute_not_exists(pk)"}},
                {"Put": {"TableName": table,
                         "Item": {"pk": {"S": prefix + "outbox:" + key}, "binding": {"S": binding}},
                         "ConditionExpression": "attribute_not_exists(pk)"}},
            ],
        )
        return {"code": "CHARGED"}
    except Exception:
        # A commit response can be lost. The durable exact intent resolves it;
        # no exception text, AWS identifiers or request contents are returned.
        try:
            item = existing()
            if item:
                return {"code": "REPLAY" if item == expected else "BINDING_CONFLICT"}
        except Exception:
            return {"code": "PROBE_UNAVAILABLE"}
        return {"code": "NOT_COMMITTED"}


def handler(event, context):
    try:
        import boto3  # supplied by the managed Python Lambda runtime
        return probe(boto3.client("dynamodb"), os.environ["PROBE_TABLE"], event)
    except Exception:
        return {"code": "PROBE_UNAVAILABLE"}
