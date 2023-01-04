"""Helpers for CSFLE implementation."""

import base64

from pymongo import MongoClient
import pymongocrypt
from pymongo.encryption_options import AutoEncryptionOpts
from pymongo.encryption import ClientEncryption
from bson.codec_options import CodecOptions
from bson.binary import Binary, STANDARD, UUID_SUBTYPE
from uuid import UUID
import os

class CsfleHelper:
    """This is a helper class that aids in csfle implementation."""

    def __init__(self,
                 kms_provider=None,
                 kms_provider_name="aws",
                 key_alt_name="demo-data-key",
                 key_db="encryption",
                 key_coll="__keyVault",
                 master_key=None,
                 schema=None,
                 connection_string= os.environ['ATLAS_CONNECTION_STRING'],
                 # setting this to True requires manually running mongocryptd
                 mongocryptd_bypass_spawn=False,
                 mongocryptd_spawn_path="mongocryptd"):
        """
        If mongocryptd is not installed to in your search path, ensure
        you override mongocryptd_spawn_path
        """
        super().__init__()
        if kms_provider is None:
            raise ValueError("kms_provider is required")
        self.kms_provider = kms_provider
        self.kms_provider_name = kms_provider_name
        self.key_alt_name = key_alt_name
        self.key_db = key_db
        self.key_coll = key_coll
        self.master_key = master_key
        self.key_vault_namespace = f"{self.key_db}.{self.key_coll}"
        self.schema = schema
        self.connection_string = connection_string
        self.mongocryptd_bypass_spawn = mongocryptd_bypass_spawn
        self.mongocryptd_spawn_path = mongocryptd_spawn_path

    def key_from_base64(base64_key):
        return Binary(base64.b64decode(base64_key), UUID_SUBTYPE)

    def ensure_unique_index_on_key_vault(self, key_vault):
        # clients are required to create a unique partial index on keyAltNames
        key_vault.create_index("keyAltNames",
                               unique=True,
                               partialFilterExpression={
                                   "keyAltNames": {
                                       "$exists": True
                                   }
                               })

    def find_or_create_data_key(self):
        """
        In the guide, https://www.mongodb.com/docs/drivers/security/client-side-field-level-encryption-guide/,
        we create the data key and then show that it is created by
        using a find_one query. Here, in implementation, we only create the key if
        it doesn't already exist, ensuring we only have one local data key.

        We also use the key_alt_names field and provide a key alt name to aid in
        finding the key in the clients.py script.
        """

        key_vault_client = MongoClient(self.connection_string)

        key_vault = key_vault_client[self.key_db][self.key_coll]

        self.ensure_unique_index_on_key_vault(key_vault)

        data_key = key_vault.find_one({"keyAltNames": self.key_alt_name})

        # create a key
        if data_key is None:
            with ClientEncryption(self.kms_provider,
                                  self.key_vault_namespace,
                                  key_vault_client,
                                  CodecOptions(uuid_representation=STANDARD)
                                  ) as client_encryption:

                # create data key using KMS master key
                return client_encryption.create_data_key(
                    self.kms_provider_name,
                    key_alt_names=[self.key_alt_name],
                    master_key=self.master_key)

        return data_key['_id'].bytes

    def get_regular_client(self):
        return MongoClient(self.connection_string)

    def get_csfle_enabled_client(self, schema):
        return MongoClient(
            self.connection_string,
            auto_encryption_opts=AutoEncryptionOpts(
                self.kms_provider,
                self.key_vault_namespace,
                mongocryptd_bypass_spawn=self.mongocryptd_bypass_spawn,
                mongocryptd_spawn_path=self.mongocryptd_spawn_path,
                schema_map=schema)
        )

    def create_json_schema(data_key, dbName, collName):
        collNamespace = f"{dbName}.{collName}"
        return {
            collNamespace: {
                "bsonType": "object",
                "encryptMetadata": {
                    "keyId": [data_key]
                },
                "properties": {
                    "icao24": {
                        "encrypt": {
                            "bsonType": "string",
                            "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
                        }
                    },
                    "callsign": {
                        "encrypt": {
                            "bsonType": "string",
                            "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Random"
                        }
                    },
                    "origin_country": {
                        "encrypt": {
                            "bsonType": "string",
                            "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
                        }
                    },
                    "velocity": {
                        "encrypt": {
                            "bsonType": "double",
                            "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Random"
                        }
                    }
                }
            }
        }