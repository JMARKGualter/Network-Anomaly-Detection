import pandas as pd
import numpy as np
from scapy.all import rdpcap
import warnings
warnings.filterwarnings('ignore')


def load_and_validate_csv(filepath):
    """
    Load CSV with automatic format detection
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
            df = pd.read_csv(filepath, encoding='utf-8', errors='ignore')
        
        # Basic validation
        if len(df) == 0:
            raise ValueError("File is empty")
        
        if len(df.columns) < 2:
            raise ValueError("File doesn't appear to contain network data")
        
        # Clean up
        df = clean_network_data(df)
        
        return df
        
    except Exception as e:
        raise Exception(f"Failed to load file: {str(e)}")


def clean_network_data(df):
    """Clean and prepare network data"""
    df_clean = df.copy()
    
    # Remove empty columns
    df_clean = df_clean.dropna(axis=1, how='all')
    
    # Try to detect and convert timestamp columns
    for col in df_clean.columns:
        if any(keyword in col.lower() for keyword in ['time', 'date', 'stamp']):
            try:
                df_clean[col] = pd.to_datetime(df_clean[col], errors='coerce')
            except:
                pass
    
    # Clean up string columns
    for col in df_clean.select_dtypes(include=['object']).columns:
        df_clean[col] = df_clean[col].astype(str).str.strip()
    
    # Try to convert numeric columns
    for col in df_clean.columns:
        try:
            df_clean[col] = pd.to_numeric(df_clean[col], errors='ignore')
        except:
            pass
    
    return df_clean


def load_pcap(filepath):
    """Load PCAP file (simplified)"""
    try:
        packets = rdpcap(filepath)
        # Convert to DataFrame (simplified)
        data = []
        for pkt in packets[:1000]:  # Limit for performance
            try:
                data.append({
                    'time': pkt.time,
                    'size': len(pkt),
                    'protocol': pkt.proto if hasattr(pkt, 'proto') else 'unknown'
                })
            except:
                pass
        
        return pd.DataFrame(data)
    except Exception as e:
        raise Exception(f"Failed to load PCAP: {str(e)}")