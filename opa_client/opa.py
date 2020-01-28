############################################
# ________      ________    ________       #
# |\   __  \    |\   __  \  |\   __  \     #
# \ \  \|\  \   \ \  \|\  \ \ \  \|\  \    #
#  \ \  \\\  \   \ \   ____\ \ \   __  \   #
#   \ \  \\\  \   \ \  \___|  \ \  \ \  \  #
#    \ \_______\   \ \__\      \ \__\ \__\ #
#     \|_______|    \|__|       \|__|\|__| #
############################################

import requests
import urllib3
import codecs
import json, os, glob
from user_agent import generate_user_agent
from typing import Union
from OpaExceptions.OpaExceptions import (
    CheckPermissionError,
    ConnectionsError,
    DeleteDataError,
    DeletePolicyError,
    PathNotFoundError,
    PolicyNotFoundError,
    RegoParseError,
    SSLError,
    FileError,
    TypeExecption
)

json_reader = codecs.getreader("utf-8")


__version__ = "1.0.6"


class OpaClient:

    """ OpaClient client object to connect and manipulate OPA service.
        ```
        The class object holds session information necesseary to connect OPA service.
        param :: host : to connect OPA service ,defaults to localhost
        type  :: host: str
        param :: port : to connect OPA service ,defaults to 8181
        type  :: port : str or int
        param :: version : provided REST API version by OPA,defaults to v1
        type  :: version : str
        param :: ssl : verify ssl certificates for https requests,defaults to False
        type  :: ssl : bool
        param :: cert : path to client certificate information to use for mutual TLS authentification
        type  :: cert : str
        param :: headers :  dictionary of headers to send, defaults to None
        ```

    """

    def __init__(
        self,
        host: str="localhost",
        port: int=8181,
        version: str="v1",
        ssl: bool=False,
        cert:Union[None,str]=None,
        headers: Union[None,dict]=None,
        **kwargs,
    ):
        host = host.lstrip()
        self.__port = port
        self.__version = version
        self.__policy_root = "{}/policies/{}"
        self.__data_root = "{}/data/{}"
        self.__secure = False
        self.__schema = "http://"

        if type(port) not in [int]:
            raise TypeError("The port must be integer")
        
        if ssl:
            self.__ssl = ssl
            self.__cert = cert
            self.__secure = True
            self.__schema = "https://"

        if not cert:
            if ssl:
                raise SSLError("ssl=True", "Make sure you  provide cert file")

        if host.startswith("https://"):
            self.__host = host
            self.__root_url = "{}:{}/{}".format(
                self.__host, self.__port, self.__version
            )

        elif host.startswith("http://"):
            self.__host = host
            if self.__secure:
                raise SSLError(
                    "ssl=True",
                    "With ssl enabled not possible to have connection with http",
                )

            self.__root_url = "{}:{}/{}".format(
                self.__host, self.__port, self.__version
            )

        else:
            self.__host = host

            self.__root_url = "{}{}:{}/{}".format(
                self.__schema, self.__host, self.__port, self.__version
            )

        if headers:
            self.__headers = requests.utils.default_headers()
            self.__headers.update({**headers})
        else:
            self.__headers = requests.utils.default_headers()

            self.__headers.update({"User-Agent": generate_user_agent()})

        if self.__secure:
            https = urllib3.PoolManager(
                cert_reqs="CERT_REQUIRED",
                assert_hostname=False,
                ca_certs=self.__cert,
                headers=self.__headers,
            )
            self.__session = https.request
        else:
            https = urllib3.PoolManager(
                headers=self.__headers
            )
            self.__session = https.request

    def check_connection(self):
        """
            Checks whether established connection config True or not.   
            if not properly configured will raise an ConnectionError.
        """
        
        url = self.__policy_root.format(self.__root_url, "")
        try:
            response = self.__session("GET", url, retries=2, timeout=1.5)
            if response.status == 200:
                return "Yes I'm here :)"

        except Exception:
            raise ConnectionsError("service unreachable", "check config and try again")

        raise ConnectionsError("service unreachable", "check config and try again")

    def get_policies_list(self) -> list:

        """ Returns all  OPA policies in the service"""

        return self.__get_policies_list()

    def get_policies_info(self) -> dict:
        """ 
            Returns information about each policy, including
            policy path and policy rules
        """
        return self.__get_policies_info()

    def update_opa_policy_fromstring(self, new_policy: str, endpoint: str) -> bool:

        """ Write your rego policy with using python string type and update your OPA policies.
            ```
            param :: new_policy : is the name of your new defined  rego policy. 
            param : endpoint : is the path of your new policy in OPA

            example:
                new_policy=
                    package play

                    default hello = false

                    hello {
                        m := input.message
                        m == "world"
                    }
                
                client = OpaClient()
                client.update_opa_policy_fromstring(new_policy,'exampleapi')
            ```

        """

        return self.__update_opa_policy_fromstring(new_policy, endpoint)

    def update_opa_policy_fromfile(self, filepath: str, endpoint: str) -> bool:

        """ Write your rego policy to file and update your OPA policies. """

        return self.__update_opa_policy_fromfile(filepath, endpoint)

    def update_opa_policy_fromurl(self, url: str, endpoint: str) -> bool:

        """Update your OPA policies from internet."""

        return self.__update_opa_policy_fromurl(url, endpoint)

    def update_or_create_opa_data(self, new_data: dict, endpoint: str) -> bool:

        """ Updates existing data or create new data for policy.
            ```
            param :: new_data : name of defined data
            type  :: new_data : dict
            param :: endpoint : is the path of your new data or existing one in OPA 
            type  :: endpoint : str
            example:
                my_policy_list = [
                    {"resource": "/api/someapi", "identity": "your_identity", "method": "PUT"},
                    {"resource": "/api/someapi", "identity": "your_identity", "method": "GET"},
                ]

                client = OpaClient()
                client.update_or_create_opa_data(my_policy_list,'exampledata/accesses')
            ```
        """

        return self.__update_opa_data(new_data, endpoint)

    def get_opa_raw_data(self, data_name):
        """Returns OPA raw data in string type """
        return self.__get_opa_raw_data(data_name)

    def opa_policy_to_file(self, policy_name: str, path: Union[str,None]=None, filename: str="opa_policy.rego"):

        """ Write OPA service policy to the  file.
        ```
            param :: policy_name : name of OPA policy
            type  :: policy_name : str

            param :: path : path to save file ,default current path
            type  :: path : str

            param :: filename : name of the file,default opa_policy.rego
            type  :: filename : str
        ```

        """
        return self.__opa_policy_to_file(policy_name, path, filename)

    def get_opa_policy(self, policy_name: str) -> dict:

        """Returns full info about policy, provided OPA service """

        return self.__get_opa_policy(policy_name)

    def delete_opa_policy(self, policy_name: str) -> bool:
        """ Deletes given OPA policy name """

        return self.__delete_opa_policy(policy_name)

    def delete_opa_data(self, data_name: str) -> bool:

        """ Deletes given OPA policy data name """

        return self.__delete_opa_data(data_name)

    def check_permission(self, input_data: dict, policy_name: str, rule_name: str) -> dict:

        """
        ```
            params :: input_data    : data which you want check permission
                type   :: input_data  : dict

            params :: policy_name   : the name of policy resource 
                type   :: policy_name  : str

            params :: rule_name   : the name included in the policy  
                type   :: rule_name  : str
        ```
        """

        return self.__check(input_data, policy_name, rule_name)

    def __get_opa_raw_data(self, data_name: str):
        url = self.__data_root.format(self.__root_url, data_name)

        response = self.__session(
            "GET", url, headers=self.__headers, retries=2, timeout=1.5
        )
        code = response.status
        response = json.loads(response.data.decode("utf-8"))
        return response if code == 200 else (code, "not found")

    def __update_opa_data(self, new_data: dict, endpoint: str):
        url = self.__data_root.format(self.__root_url, endpoint)

        encoded_json = json.dumps(new_data).encode("utf-8")
        response = self.__session(
            "PUT",
            url,
            body=encoded_json,
            headers=self.__headers,
            retries=2,
            timeout=1.5,
        )
        code = response.status
        return True if code == 204 else False

    def __update_opa_policy_fromfile(self, filepath: str, endpoint: str):

        if os.path.isfile(filepath):
            with open(filepath, "r") as rf:
                return self.__update_opa_policy_fromstring(rf.read(), endpoint)
        
        
        raise FileError(f"{filepath}", "is not a file, make sure you provide a file")

    def __update_opa_policy_fromstring(self, new_policy: str, endpoint: str) -> bool:

        if not isinstance(new_policy,str) or not isinstance(endpoint,str):
            raise TypeExecption(f"{new_policy} is not string type")

        if new_policy:
            url = self.__policy_root.format(self.__root_url, endpoint)

            response = self.__session(
                "PUT",
                url,
                body=new_policy.encode(),
                headers=self.__headers,
                retries=2,
                timeout=1.5,
            )

            if response.status == 200:
                return True

            raise RegoParseError(
                json.loads(response.data.decode()).get("code"),
                json.loads(response.data.decode()).get("message"),
            )

        return False

    def __get_opa_policy(self, policy_name: str) -> dict:
        url = self.__policy_root.format(self.__root_url, policy_name)

        response = self.__session(
            "GET", url, headers=self.__headers, retries=2, timeout=1.5
        )
        data = json.loads(response.data.decode("utf-8"))
        if response.status == 200:

            return data

        raise PolicyNotFoundError(data.get("code"), data.get("message"))

    def __update_opa_policy_fromurl(self, url: str, endpoint: str) -> bool:
        response = requests.get(url, headers=self.__headers)
        return self.__update_opa_policy_fromstring(response.text, endpoint)

    def __opa_policy_to_file(self, policy_name: str, path: Union[str,None], filename: str) -> bool:
        raw_policy = self.__get_opa_policy(policy_name)
        if isinstance(raw_policy, dict):
            try:
                if path:

                    with open(f"{path}/{filename}", "wb") as wr:
                        wr.write(raw_policy.get("result").get("raw").encode())
                else:
                    with open(filename, "wb") as wr:
                        wr.write(raw_policy.get("result").get("raw").encode())
                return True

            except:
                raise PathNotFoundError("error when write file", "path not found")

    def __delete_opa_policy(self, policy_name: str) -> bool:
        url = self.__policy_root.format(self.__root_url, policy_name)
 
        response = self.__session(
            "DELETE", url, headers=self.__headers, retries=2, timeout=1.5
        )
        data = json.loads(response.data.decode("utf-8"))
        if response.status == 200:

            return True

        raise PolicyNotFoundError(data.get("code"), data.get("message"))

    def __get_policies_list(self) -> list:
        url = self.__policy_root.format(self.__root_url, "")
        temp = []
        response = self.__session(
            "GET", url, retries=2, timeout=1.5, headers=self.__headers
        )

        response = json.loads(response.data.decode())

        for policy in response.get("result"):
            if policy.get("id"):
                temp.append(policy.get("id"))

        return temp

    def __delete_opa_data(self, data_name: str) -> bool:
        url = self.__data_root.format(self.__root_url, data_name)

        response = self.__session(
            "DELETE", url, headers=self.__headers, retries=2, timeout=1.5
        )
        if response.data:
            data = json.loads(response.data.decode("utf-8"))
        if response.status == 204:

            return True

        raise DeleteDataError(data.get("code"), data.get("message"))

    def __get_policies_info(self) -> dict:
        url = self.__policy_root.format(self.__root_url, "")
        policy = self.__session(
            "GET", url, retries=2, timeout=1.0, headers=self.__headers
        )

        policy = json.loads(policy.data.decode())
        result = policy.get("result")

        permission_url = self.__root_url
        temp_dict = {}
        temp_policy = []
        temp_rules = []
        for policy in result:
            temp_policy = []
            temp_rules = []
            temp_url = ""
            permission_url = self.__root_url
            for path in policy.get("ast").get("package").get("path"):
                permission_url += "/" + path.get("value")
            temp_policy.append(permission_url)
            for rule in policy.get("ast").get("rules"):
                if not rule.get("default"):
                    continue
                temp_url = permission_url
                temp_url += "/" + rule.get("head").get("name")
                temp_rules.append(temp_url)
            temp_dict[policy.get("id")] = {"path": temp_policy, "rules": temp_rules}

        return temp_dict

    def __check(self, input_data: dict, policy_name: str, rule_name: str) -> dict:
        url = self.__policy_root.format(self.__root_url, policy_name)

        policy = self.__session(
            "GET", url, headers=self.__headers, retries=2, timeout=1.5
        )
        policy = json.loads(policy.data.decode("utf-8"))
        result = policy.get("result")
        find = False
        permission_url = self.__root_url
        if result:
            for path in result.get("ast").get("package").get("path"):
                permission_url += "/" + path.get("value")

            for rule in result.get("ast").get("rules"):
                if not rule.get("default"):
                    continue
                if rule.get("head").get("name") == rule_name:

                    permission_url += "/" + rule.get("head").get("name")
                    find = True
        if find:

            encoded_json = json.dumps(input_data).encode("utf-8")
            response = self.__session(
                "POST", permission_url, body=encoded_json, retries=2, timeout=1.5
            )
            if response.data:
                data = json.loads(response.data.decode("utf-8"))
                return data

        raise CheckPermissionError(
            f"{rule_name} rule not found", "policy or rule name not correct"
        )

    @property
    def _host(self):
        return self.__host
    
    @property
    def _port(self):
        return self.__port
    
    @property
    def _version(self):
        return self.__version
    
    @property
    def _root_url(self):
        return self.__root_url
    
    @property
    def _schema(self):
        return self.__schema

    @property
    def _policy_root(self):
        return self.__policy_root
    
    @property
    def _data_root(self):
        return self.__data_root
    
    @property
    def _secure(self):
        return self.__secure

    @property
    def _ssl(self):
        return self.__ssl
    
    @property
    def _cert(self):
        return self.__cert
