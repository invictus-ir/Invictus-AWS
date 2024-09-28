"""File containg all the aws enumeration function used to get data."""

from source.utils.utils import fix_json, try_except
import source.utils.utils
from tqdm import tqdm

def s3_lookup():
    """Return all existing buckets.
    
    Returns
    -------
    elements : list
        List of the existing buckets
    """
    response = try_except(source.utils.utils.S3_CLIENT.list_buckets)
    buckets = fix_json(response)

    elements = []
    elements = buckets.get("Buckets", [])

    return elements

def ec2_lookup():
    """Return all ec2 instances.

    Returns
    -------
    elements : list
        List of the existing ec2 instances

    """
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
        print(f"[!] invictus-aws.py: error: {str(e)}")  

    return elements  

def simple_paginate(client, command, **kwargs):
    """Return all the results of the command, no matter the number of results.
    
    Parameters
    ----------
    client : str
        Name of the client used to call the request (S3, LAMBDA, etc)
    command : str
        Command executed
    **kwargs : list, optional
        List of parameters to add to the command.

    Returns
    -------
    elements : list
        List of the results of the command
    """
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
        print(f"[!] invictus-aws.py: error: {str(e)}")  

    return elements  

def paginate(client, command, array, **kwargs):
    """Do the same as the previous function, but we can then filter the results on a specific part of the response.

    Parameters
    ----------
    client : str
        Name of the client used to call the request (S3, LAMBDA, etc)
    command : str
        Command executed
    array : str
        Filter added to get a specific part of the results
    **kwargs : list, optional
        List of parameters to add to the command.

    Returns
    -------
    elements : list
        List of the results of the command
    """
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
            print(f"[!] invictus-aws.py: error: {str(e)}")  

    return elements  

def simple_misc_lookup(client, function, name_token, **kwargs):
    """Return all the results of the command, no matter the number of results. Used by functions not usable by paginate.

    Parameters
    ----------
    client : str
        Name of the client (S3, LAMBDA, etc) only used for the progress bar
    function : str
        Concatenation of the client and the command (CLIENT.COMMAND)
    name_token : str
        Name of the token used by the command to get the other pages of results.    
    **kwargs : list, optional
        List of parameters to add to the command.

    Returns
    -------
    elements : list
        List of the results of the command
    """
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

def misc_lookup(client, function, name_token, array, **kwargs):
    """Do the same as the previous function, but we can then filter the results on a specific part of the response. Used by functions not usable by paginate.

    Parameters
    ----------
    client : str
        Name of the client (S3, LAMBDA, etc) only used for the progress bar
    function : str
        Concatenation of the client and the command (CLIENT.COMMAND)
    name_token : str
        Name of the token used by the command to get the other pages of results.   
    array : str
        Filter added to get a specific part of the results 
    **kwargs : list, optional
        List of parameters to add to the command.

    Returns
    -------
    elements : list
        List of the results of the command
    """
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

def list_traffic_policies_lookup(function):
    """Get all the results of the list_traffic_policies command of the route53 client.

    Parameters
    ----------
    function : str
        Concatenation of the client and the command

    Returns
    -------
    elements : list
        List of the results of the command
    """
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
