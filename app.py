from helpers import CsfleHelper
from opensky_api import OpenSkyApi
import pymongo
import datetime
from time import sleep
import os

# set env variables ACCESS_KEY, SECRET_KEY
def main():
    kms_provider_name = "aws"
    kms_providers = {
        "aws": {
            "accessKeyId": os.environ['ACCESS_KEY'],
            "secretAccessKey": os.environ['SECRET_KEY']
        }
    }

# set env variable CMK
    master_key = {
        "region": os.environ['KEY_REGION'],
        "key": os.environ['CMK']
    }

    keyDb = "encryption"
    keyColl = "__keyVault"
    
    dataDb = "testdb"
    dataColl = "actualcollection"

    csfle_helper = CsfleHelper(kms_provider_name=kms_provider_name,
                               kms_provider=kms_providers, master_key=master_key, key_db=keyDb, key_coll=keyColl)

    # if you already have a data key or are using a remote KMS, uncomment the line below
    data_key = csfle_helper.find_or_create_data_key()

    # set a JSON schema for automatic encryption
    schema = CsfleHelper.create_json_schema(
        data_key=data_key[0], dbName=dataDb, collName=dataColl)
    #print(schema)
    
    encrypted_client = csfle_helper.get_csfle_enabled_client(schema)

    api = OpenSkyApi()
    states = api.get_states()
    for s in states.states:
        document = {
            "isotime" : datetime.datetime.now().isoformat(),
            "icao24" : s.icao24,
            "callsign" : s.callsign,
            "origin_country" : s.origin_country,
            "time_position" : s.time_position,
            "last_contact" : s.last_contact,
            "longitude" : s.longitude,
            "latitude" : s.latitude,
            "geo_altitude" : s.geo_altitude,
            "on_ground" : s.on_ground,
            "velocity" : s.velocity,
            "true_track" : s.true_track,
            "vertical_rate" : s.vertical_rate,
            "sensors" : s.sensors,
            "baro_altitude" : s.baro_altitude,
            "squawk" : s.squawk,
            "spi" : s.spi,
            "position_source" : s.position_source,
        }
    
        # performing the insert operation with the CSFLE-enabled client
        # we're using an update with upsert so that subsequent runs of this script don't
        # add more documents
        encrypted_client.testdb.actualcollection.update_one(
            {"origin_country": document["origin_country"]},
            {"$set": document}, upsert=True)
        
        # perform a read using the csfle enabled client. We expect all fields to
        # be readable.
        # querying on an encrypted field using strict equality
        csfle_find_result = encrypted_client.testdb.actualcollection.find_one(
            {"origin_country": document["origin_country"]})
        print(
            f"Document retrieved with csfle enabled client:\n{csfle_find_result}\n")

        # perform a read using the regular client. We expect some fields to be
        # encrypted.
        regular_client = csfle_helper.get_regular_client()
        regular_find_result = regular_client.testdb.actualcollection.find_one({
                                                                    "spi": "false"})
        print(f"Document found regular_find_result:\n{regular_find_result}")
        sleep(20)
    regular_client.close()
    encrypted_client.close()
    
if __name__ == "__main__":
    main()