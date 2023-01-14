#!/usr/bin/env python3
# encoding: utf-8
"""

netskope-client.py

Created by Mark van der Meulen 2022.
Copyright (c) 2022 Mark van der Meulen. All rights reserved.

"""
import time
import requests
import json
import datetime
import pathlib
import sys
from pydantic import BaseModel, AnyHttpUrl, UUID4, Json
from typing import List, Dict, Optional, Callable
from enum import Enum


__author__ = "Mark van der Meulen"
__status__ = "Testing/Unstable"


'''
Netskope API Request and Response Schemas
See documentation here: https://docs.netskope.com/en/private-access-rest-apis.html
'''


class AppModificationStatus(str, Enum):
    modified = 'modified'
    unchanged = 'unchanged'


class NetskopeQueryStatus(str, Enum):
    success = 'success'
    error = 'error'


class NetskopeBaseResponse(BaseModel):
    status: NetskopeQueryStatus
    data: Optional[Dict]
    # data: Optional[Json]


class NetskopePrivateAppProtocol(BaseModel):
    type: str
    port: str


class NetskopePrivateAppPublisherIdentity(BaseModel):
    publisher_id: str
    publisher_name: str


class NetskopePublisherReachability(BaseModel):
    error_code: int
    error_string: str
    reachable: bool


class NetskopePublisherAssessment(BaseModel):
    eee_support: bool
    hdd_free: str
    hdd_total: str
    ip_address: str
    version: str


class NetskopePublisherUpgradeStatus(BaseModel):
    upstat: str


class NetskopePublisherAssignment(BaseModel):
    primary: Optional[bool] = None
    publisher_id: int
    # unfortunately sometimes the data does not have a correct reachability section
    # Hence why I have had to add NetskopePublisherReachability as an Optional
    reachability: Optional[NetskopePublisherReachability]
    service_id: int


class NetskopePrivateApp(BaseModel):
    app_id: int
    app_name: str
    service_publisher_assignments: List[NetskopePublisherAssignment]


class NetskopePublisherDetail(BaseModel):
    assessment: NetskopePublisherAssessment
    common_name: str
    publisher_id: int
    publisher_name: str
    publisher_upgrade_profiles_external_id: int
    registered: bool
    # status: may be better served by an enum
    status: str
    stitcher_id: int
    tags: List[str] = None
    upgrade_failed_reason: Optional[str] = None
    upgrade_request: bool
    upgrade_status: NetskopePublisherUpgradeStatus


'''
Publisher APIs: Responses
'''


class NetskopeGetPublisherData(BaseModel):
    publisher: NetskopePublisherDetail


class NetskopeGetPublishersData(BaseModel):
    publishers: List[NetskopePublisherDetail]


class NetskopeGetPublisherResponse(NetskopeBaseResponse):
    '''
    Schema for the entire JSON container returned by the API.
    Two fields: status, data
    '''
    data: NetskopeGetPublisherData


class NetskopeGetPublishersResponse(NetskopeBaseResponse):
    '''
    Schema for the entire JSON container returned by the API.
    Two fields: status, data
    '''
    data: NetskopeGetPublishersData


'''
Private Apps API: Responses
'''


class NetskopeGetAppData(BaseModel):
    private_app: NetskopePrivateApp


class NetskopeGetAppsData(BaseModel):
    private_apps: List[NetskopePrivateApp]


class NetskopeGetAppResponse(NetskopeBaseResponse):
    '''
    Schema for the entire JSON container returned by the API.
    Two fields: status, data
    '''
    data: NetskopeGetAppData


class NetskopeGetAppsResponse(NetskopeBaseResponse):
    '''
    Schema for the entire JSON container returned by the API.
    Two fields: status, data
    '''
    data: NetskopeGetAppsData


'''
Private Apps API: Query Schema
'''


class NetskopeAppPatchSchema(BaseModel):
    app_id: int
    app_name: str
    clientless_access: int
    host: str
    private_app_protocol: str
    protocols: List = []
    reachability: int
    real_host: str
    tags: List = []
    trust_self_signed_certs: int
    use_publisher_dns: int
    id: int
    publishers: List = []


##
# API Client & Helpers
##

class NetskopeTokenAuth(requests.auth.AuthBase):
    '''Implements a simple adapter for custom auth'''

    def __init__(self, token):
        self.token = token

    def __call__(self, r):
        '''Attaches API token to custom auth header'''
        # r.headers['X-Auth-Token'] = f'{self.token}'
        r.headers['Netskope-Api-Token'] = f'{self.token}'
        return r


class RestClient(object):
    '''
    Framework for a client
    '''

    def __init__(self, url: AnyHttpUrl = None, token: str = None):
        '''
        Sets URL if provided and creates a new request object.
        '''
        self.baseurl = url if url is not None else 'https://tenant.goskope.com'
        self.client = requests.session()
        self.headers = {}
        self.set_token(token)
        self.set_headers()

    def set_token(self, token: str = None) -> None:
        '''
        Sets token to use in Bearer
        '''
        # self.token = token
        self.token = NetskopeTokenAuth(token) if token is not None else None

    def set_headers(self) -> None:
        '''
        Sets headers.
        '''
        self.headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

    def post(self, url: str = None, token: str = None, payload: Dict = None, timeout: int = 2, cb: Callable = None, status_code_success: int = None, ResponseSchema: BaseModel = None) -> NetskopeBaseResponse:
        '''
        Executes HTTP POST method with supplied parameters.
        '''
        try:
            response = self.client.post(
                f'{self.base_url}{url}', headers=self.headers, json=json.dumps(payload), timeout=timeout)
            response.raise_for_status()
        except requests.exceptions.HTTPError as http_err:
            print(http_err)
        else:
            if response.status_code == 200:
                return response.json()

    def patch(self, url: str = None, token: str = None, payload: BaseModel = None, timeout: int = 2, cb: Callable = None, status_code_success: int = None, ResponseSchema: BaseModel = None) -> NetskopeBaseResponse:
        '''
        Executes HTTP PATCH method with supplied parameters.
        '''
        if isinstance(payload, BaseModel):
            payload_data = json.dumps(payload.json())
        else:
            payload_data = json.dumps(payload)
        try:
            response = self.client.patch(
                f'{self.base_url}{url}', headers=self.headers, data=payload_data, timeout=timeout)
            response.raise_for_status()
        except requests.exceptions.HTTPError as http_err:
            print(http_err)
            raise
        else:
            status_code_success = status_code_success if status_code_success is not None else 200
            # Remember that HTTP 204 actually is used as follows.
            # HTTP 204 No Content: The server successfully processed the request, but is not returning any content
            # Therefore if the response is 204 we should return the code only.
            if response.status_code == status_code_success:
                if ResponseSchema:
                    data = json.loads(response.json())
                    return ResponseSchema(**data)
                else:
                    return response.json()
            elif response.status_code < 300 and response.status_code >= 200:
                return response.json()

    def put(self, url: str = None, token: str = None, payload: Dict = None, timeout: int = 2, cb: Callable = None) -> NetskopeBaseResponse:
        '''
        Executes HTTP PUT method with supplied parameters.
        '''
        try:
            response = self.client.put(
                f"{self.base_url}{url}", headers=self.headers)
            response.raise_for_status()
        except requests.exceptions.HTTPError as http_err:
            print(http_err)
        else:
            if response.status_code == 200:
                return response.json()
        # data = [{'status': 1}, ]
        # return data

    def get(self, url: str = None, token: str = None, payload: Dict = None, timeout: int = 5, cb: Callable = None, status_code_success: int = None, ResponseSchema: BaseModel = None) -> NetskopeBaseResponse:
        '''
        Executes HTTP GET method with supplied parameters.
        '''
        try:
            response = self.client.get(
                f"{self.base_url}{url}", headers=self.headers, timeout=timeout)
            response.raise_for_status()
        except requests.exceptions.HTTPError as http_err:
            print(http_err)
            raise
        else:
            status_code_success = status_code_success if status_code_success is not None else 200
            if response.status_code == status_code_success:
                if ResponseSchema:
                    data = json.loads(response.json())
                    return ResponseSchema(**data)
                else:
                    return response.json()
            elif response.status_code < 300 and response.status_code >= 200:
                return response.json()


def get_all_apps(client: RestClient, filter: List[str] = None) -> NetskopeGetAppsData:
    '''
    The filter parameter should be a list of fields to filter by. ie.
    filter=['app_id','app_name','service_publisher_assignments']
    If no filter list is provided, no filtering will take place.
    '''
    path = '/api/v2/steering/apps/private'
    if filter:
        filter_fields_string = '%2C'.join(filter)
        path = f'{path}?fields={filter_fields_string}'
    # The question, now that it is obvious we are performing filtering is how does that
    # impact our response model. Current response model expects the filtered schema only.
    nsrequest = client.get(url=path, ResponseSchema=NetskopeGetAppsResponse)
    return nsrequest.data


def get_app(client: RestClient, id: str) -> NetskopeGetAppData:
    '''
    It is unlikely that the Netskope will simply return a data structure
    identical to NetskopePrivateApp. More likely that it is similar to the standard
    container.
    '''
    path = f'/api/v2/steering/apps/private/{id}'
    nsrequest = client.get(url=path, ResponseSchema=NetskopeGetAppResponse)
    return nsrequest.data


def patch_app(client: RestClient, payload: NetskopeAppPatchSchema) -> NetskopeBaseResponse:
    '''
    Remember the app_id is in the path as well as the payload.
    '''
    path = f'/api/v2/steering/apps/private/{payload.app_id}'
    result = client.patch(url=path, payload=payload,
                          ResponseSchema=NetskopeBaseResponse)
    return result


def find_and_resolve_app_issues(app) -> (AppModificationStatus, NetskopeAppPatchSchema):
    '''
    This is where we should resolve any inconsistencies and then
    return the data ready to be sent to the API.
    Do we want to upload here once fixed or separately?
    I say separately for the sake of rate limiting.
    '''
    pass


def dt() -> datetime.datetime:
    '''
    Timestamp helper.
    '''
    return datetime.datetime.now()


def log(msg, app: NetskopePrivateApp = None) -> None:
    '''
    Simple log printing utility function
    '''
    if app:
        msg = f'[{app.app_id}] {msg}'
    print(f'{dt()} {msg}')


def load_test_data(filename: str, path: str = None, Schema: BaseModel = None):
    if not path:
        path = pathlib.Path(__file__).parent
    fp = pathlib.Path.joinpath(path, filename)
    if not pathlib.Path.exists(fp) or not pathlib.Path.is_file(fp):
        raise ValueError(f'Invalid file path specified: {fp}')
    try:
        with open(fp, 'r') as j:
            json_file_data = json.load(j)
    except IOError:
        log(f'Error loading data from file: {fp}')
    else:
        if not Schema:
            return json_file_data
        return Schema(**json_file_data)


def test_load_schemas(params: List) -> List:
    '''
    params: List of tuples containing (Filepath, Schema)
    ie. [('all_private_apps.json', NetskopeGetAppsResponse) ]
    '''
    data = []
    for fname, fSchema in params:
        log(f'Loading data from {fname} into schema model {fSchema.__name__}')
        result = load_test_data(fname, Schema=fSchema)
        if result:
            data.append((fname, fSchema.__name__, result))
    return data


def run_tests():
    load_tests = test_load_schemas(
        [('all_private_apps.json', NetskopeGetAppsResponse), ])
    log('All tests were run succesfully.')


def verify_and_update_apps(client: RestClient, apps: NetskopeGetAppsData):
    # Loop through the individual app objects, clean them up and
    # push the changes to the API (using the PATCH method).
    for app in apps.private_apps:
        log(f'Processing {app.app_name}', app=app)
        status, result = find_and_resolve_app_issues(app)
        # Need to determine whether the app has been modified and requires re-uploading.
        if status == 'modified':
            log('App has been modified and will be pushed to Netskope', app=app)
            update = patch_app(client, payload=result)
            log(f'Patch request for {result.app_name} status: {update.status}', app=app)
            time.sleep(2)
        else:
            log(f'App {result.app_name} was not changed. Skipping server update', app=app)


def main(tenant: str, token: str):
    client = RestClient(url=f'https://{tenant}.goskope.com', token=token)
    # Request a field filtered view of all apps
    apps = get_all_apps(
        client, ['app_id', 'app_name', 'service_publisher_assignments'])
    # time to do the actual work
    verify_and_update_apps(client, apps)


if __name__ == "__main__":
    try:
        action = sys.argv[1]
    except IndexError:
        print("Usage: python3 netskope-client.py [test|run] [tenancy] [token]")
        exit(1)
    if action == 'test':
        run_tests()
    elif action == 'run':
        try:
            tenancy, token = str(sys.argv[2]), str(sys.argv[3])
        except IndexError:
            print("Usage: python3 netskope-client.py [test|run] [tenancy] [token]")
            exit(1)
        else:
            main(tenancy, token)
