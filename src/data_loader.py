import pandas as pd
import numpy as np
from scapy.all import rdpcap
import warnings

warnings.filterwarnings('ignore')


def load_and_validate_csv(filepath):
    """
    Load CSV with automatic format detection and validation
    """
    try:
        # Try different encodings
        encodings = ['utf-8', 'latin1', 'iso-8859-1', 'cp1252']

        for encoding in encodings:
            try:
                df = pd.read_csv(filepath, encoding=encoding)
                break
            except UnicodeDecodeError:
                continue
        else:
            # If all encodings fail, try without specifying
            df = pd.read_csv(filepath, encoding='utf-8', errors='ignore')

        # Validate that we have network-like data
        if len(df) == 0:
            raise ValueError("File is empty")

        if len(df.columns) < 3:
            raise ValueError("File doesn't appear to contain network data (too few columns)")

        # Basic cleaning
        df = clean_network_data(df)

        return df

    except Exception as e:
        raise Exception(f"Failed to load CSV: {str(e)}")


def clean_network_data(df):
    """
    Clean and prepare network data
    """
    df_clean = df.copy()

    # Remove empty columns
    df_clean = df_clean.dropna(axis=1, how='all')

    # Convert timestamp-like columns
    timestamp_cols = [col for col in df_clean.columns
                      if any(keyword in col.lower()
                             for keyword in ['time', 'date', 'stamp'])]

    for col in timestamp_cols:
        try:
            df_clean[col] = pd.to_datetime(df_clean[col], errors='coerce')
        except:
            pass

    # Clean IP addresses
    ip_cols = [col for col in df_clean.columns
               if any(keyword in col.lower()
                      for keyword in ['ip', 'src', 'dst', 'addr'])]

    for col in ip_cols:
        if df_clean[col].dtype == 'object':
            # Remove whitespace
            df_clean[col] = df_clean[col].astype(str).str.strip()

    # Convert numeric columns
    for col in df_clean.select_dtypes(include=['object']).columns:
        try:
            df_clean[col] = pd.to_numeric(df_clean[col], errors='ignore')
        except:
            pass

    return df_clean


def detect_network_features(df):
    """
    Detect what type of network data we have
    """
    features = {
        'has_timestamps': False,
        'has_ips': False,
        'has_ports': False,
        'has_protocols': False,
        'has_packet_info': False,
        'data_type': 'unknown'
    }

    cols_lower = [col.lower() for col in df.columns]

    # Check for timestamp
    time_keywords = ['time', 'timestamp', 'date']
    features['has_timestamps'] = any(any(kw in col for kw in time_keywords)
                                     for col in cols_lower)

    # Check for IP addresses
    ip_keywords = ['ip', 'src', 'dst', 'addr', 'source', 'destination']
    features['has_ips'] = any(any(kw in col for kw in ip_keywords)
                              for col in cols_lower)

    # Check for ports
    port_keywords = ['port', 'srcport', 'dstport']
    features['has_ports'] = any(any(kw in col for kw in port_keywords)
                                for col in cols_lower)

    # Check for protocols
    protocol_keywords = ['proto', 'protocol', 'type']
    features['has_protocols'] = any(any(kw in col for kw in protocol_keywords)
                                    for col in cols_lower)

    # Check for packet info
    packet_keywords = ['size', 'length', 'bytes', 'packet']
    features['has_packet_info'] = any(any(kw in col for kw in packet_keywords)
                                      for col in cols_lower)

    # Determine data type
    if features['has_timestamps'] and features['has_ips']:
        if features['has_ports']:
            features['data_type'] = 'flow_data'
        else:
            features['data_type'] = 'packet_data'
    elif features['has_packet_info']:
        features['data_type'] = 'packet_stats'

    return features