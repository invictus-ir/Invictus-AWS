from source.utils.utils import fix_json, try_except, S3_CLIENT
import source.utils.utils
from tqdm import tqdm

'''
Used to return all buckets
'''
def s3_lookup():
     
    response = try_except(S3_CLIENT.list_buckets)
    buckets = fix_json(response)

    elements = []
    elements = buckets.get("Buckets", [])

    return elements

'''
Used to return all ec2 instances
The basic paginate function can't actually work
'''

def ec2_lookup():
    elements = []
    paginator = source.utils.utils.EC2_CLIENT.get_paginator("describe_instances")
    
    try:
        with tqdm(desc=f"[+] Getting EC2 data", leave=False) as pbar:
            for page in paginator.paginate():
                page.pop("ResponseMetadata", None)
                page = fix_json(page)
                if page["Reservations"]:
                    elements.extend(page["Reservations"][0]["Instances"])
                pbar.update()
    except Exception as e:
        print(f"[!] Error : {str(e)}")  

    return elements  

'''
Return all the results of the command, no matter the number of results 
client : Client used to call the command
command : Command executed
'''
def simple_paginate(client, command, **kwargs):
    elements = []
   
    paginator = client.get_paginator(command)
    
    try:
        with tqdm(desc=f"[+] Getting {client.meta.service_model.service_name.upper()} data", leave=False) as pbar:
            for page in paginator.paginate(**kwargs):
                page.pop("ResponseMetadata", None)
                page = fix_json(page)
                elements.append(page)
                pbar.update() 
    except Exception as e:
        print(f"[!] Error : {str(e)}")  

    return elements  

'''
Same as the previous function, but we can then filter the results on a specific part of the response 
client : Client used to call the command
command : Command executed
array : Specific array of the response to return 
'''
def paginate(client, command, array, **kwargs):
    elements = []
    paginator = client.get_paginator(command)
    
    try:
        with tqdm(desc=f"[+] Getting {client.meta.service_model.service_name.upper()} data", leave=False) as pbar:
            for page in paginator.paginate(**kwargs):
                page.pop("ResponseMetadata", None)
                page = fix_json(page)
                elements.extend(page.get(array, []))
                pbar.update() 
    except Exception as e:
        if client != source.utils.utils.MACIE_CLIENT and "Macie is not enabled" not in str(e):
            print(f"[!] Error : {str(e)}")  

    return elements  

'''
Return all the results of the command, no matter the number of results. Used by functions not usable by paginate.
Useful for the commands that had to possible pagination (verifyable with client.can_paginate(command))
function : Concatenation of the client and the command (CLIENT.COMMAND)
name_token : Name of the token to get to search for remaining results
'''
def simple_misc_lookup(client, function, name_token, **kwargs):

    tokens = []

    elements  = []
    response = try_except(function, **kwargs)
    response.pop("ResponseMetadata", None)
    response = fix_json(response)
    elements = response
    
    token = ""
    if name_token in response:
        token = response.get(name_token)

    with tqdm(desc=f"[+] Getting {client} configuration", leave=False) as pbar:
        while token:
            response = try_except(function, **kwargs)
            response.pop("ResponseMetadata", None)
            response = fix_json(response)

            token = ""
            if name_token in response:
                token = response.get(name_token)
                if tokens[-1] == token:
                    break
                else:
                    elements.extend(response)
                    tokens.append(token)
            pbar.update()

    return elements

'''
Same as the previous function, but we can then filter the results on a specific part of the response. Used by functions not usable by paginate.
function : Concatenation of the client and the command (CLIENT.COMMAND)
name_token : Name of the token to get to search for remaining results
array : Specific array of the response to return 
'''
def misc_lookup(client, function, name_token, array, **kwargs):

    tokens = []

    elements  = []
    response = try_except(function, **kwargs)
    response.pop("ResponseMetadata", None)
    response = fix_json(response)
    elements.extend(response.get(array, []))
    
    token = ""
    if name_token in response:
        token = response.get(name_token)
        tokens.append(token)

    with tqdm(desc=f"[+] Getting {client} configuration", leave=False) as pbar:
        while token:
            response = try_except(function, **kwargs)
            response.pop("ResponseMetadata", None)
            response = fix_json(response)

            token = ""
            if name_token in response:
                token = response.get(name_token)
                if tokens[-1] == token:
                    break
                else:
                    elements.extend(response.get(array, []))
                    tokens.append(token)
            pbar.update()

    return elements

'''
Get all the results of the list_traffic_policies command of the route53 client
function : Concatenation of the client and the command
'''
def list_traffic_policies_lookup(function):
    elements  = []
    response = try_except(function, MaxItems="100")
    response.pop("ResponseMetadata", None)
    elements = fix_json(response)

    token = ""
    if response["IsTruncated"] == True:
        token = response["TrafficPolicyIdMarker"]

    with tqdm(desc=f"[+] Getting ROUTE53 configuration", leave=False) as pbar:
        while token:
            response = try_except(function, MaxItems="100")
            response.pop("ResponseMetadata", None)
            response = fix_json(response)
            elements.extend(response)

            token = ""
            if response["IsTruncated"] == True:
                token = response["TrafficPolicyIdMarker"]
            pbar.update()

    return elements
