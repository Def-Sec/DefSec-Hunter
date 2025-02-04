import re
import socket

def validate_target(target):
    """
    Validates if the target is a valid domain name or IP address
    """
    # Check if it's an IP address
    try:
        socket.inet_aton(target)
        return True
    except socket.error:
        pass

    # Check if it's a valid domain name
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    if re.match(domain_pattern, target):
        return True

    return False
