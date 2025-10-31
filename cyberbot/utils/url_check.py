"""
URL and Domain Check Utilities
Provides functions to check domain registration information
"""

import re
import socket
import whois
import datetime
from urllib.parse import urlparse

def extract_domain(url):
    """
    Extract domain from URL
    
    Args:
        url (str): URL to extract domain from
        
    Returns:
        str: Domain name or None if invalid
    """
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Remove www. if present
        if domain.startswith('www.'):
            domain = domain[4:]
            
        return domain if domain else None
    except:
        return None

def check_domain_age(domain):
    """
    Check domain registration age
    
    Args:
        domain (str): Domain name to check
        
    Returns:
        dict: Domain information including age and registration date
    """
    result = {
        "domain": domain,
        "is_registered": False,
        "creation_date": None,
        "age_days": None,
        "is_new": False,
        "registrar": None,
        "error": None
    }
    
    try:
        # Get WHOIS information
        domain_info = whois.whois(domain)
        
        # Check if domain is registered
        if domain_info.domain_name is None:
            result["error"] = "Domain not found"
            return result
        
        result["is_registered"] = True
        result["registrar"] = domain_info.registrar
        
        # Get creation date
        creation_date = domain_info.creation_date
        
        # Handle multiple creation dates (some WHOIS servers return a list)
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if creation_date:
            result["creation_date"] = creation_date.strftime("%Y-%m-%d")
            
            # Calculate age in days
            age_days = (datetime.datetime.now() - creation_date).days
            result["age_days"] = age_days
            
            # Consider domains less than 60 days old as "new"
            result["is_new"] = age_days < 60
    
    except Exception as e:
        result["error"] = str(e)
    
    return result