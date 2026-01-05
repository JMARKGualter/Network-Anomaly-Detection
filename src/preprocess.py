import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, MinMaxScaler, LabelEncoder
import warnings

warnings.filterwarnings('ignore')


def preprocess_data(df, method='standard'):
    """
    Enhanced preprocessing pipeline with multiple options
    """

    processed_df = df.copy()

    # 1. Handle missing values
    if processed_df.isnull().sum().sum() > 0:
        print(f"Found {processed_df.isnull().sum().sum()} missing values")

        # For numeric columns, fill with median
        numeric_cols = processed_df.select_dtypes(include=[np.number]).columns
        for col in numeric_cols:
            processed_df[col] = processed_df[col].fillna(processed_df[col].median())

        # For categorical, fill with mode
        categorical_cols = processed_df.select_dtypes(include=['object']).columns
        for col in categorical_cols:
            processed_df[col] = processed_df[col].fillna(processed_df[col].mode()[0])

    # 2. Encode categorical variables
    categorical_cols = processed_df.select_dtypes(include=['object']).columns
    label_encoders = {}

    for col in categorical_cols:
        if col not in ['timestamp', 'datetime']:  # Skip timestamp columns
            le = LabelEncoder()
            processed_df[col] = le.fit_transform(processed_df[col].astype(str))
            label_encoders[col] = le

    # 3. Feature scaling
    numeric_cols = processed_df.select_dtypes(include=[np.number]).columns

    # Remove label column if exists
    if 'label' in numeric_cols:
        numeric_cols = numeric_cols.drop('label')

    if method == 'standard':
        scaler = StandardScaler()
    elif method == 'minmax':
        scaler = MinMaxScaler()
    elif method == 'robust':
        from sklearn.preprocessing import RobustScaler
        scaler = RobustScaler()
    else:
        scaler = StandardScaler()

    processed_df[numeric_cols] = scaler.fit_transform(processed_df[numeric_cols])

    # 4. Feature engineering (add new features)
    processed_df = add_engineered_features(processed_df)

    print(f"Preprocessing completed. Shape: {processed_df.shape}")
    return processed_df


def add_engineered_features(df):
    """Add engineered features for better detection"""

    # 1. Packet size ratio (if src/dst IPs exist)
    if 'src_ip' in df.columns and 'dst_ip' in df.columns:
        # Group by source-destination pairs
        df['flow_id'] = df['src_ip'].astype(str) + '_' + df['dst_ip'].astype(str)

    # 2. Temporal features (if timestamp exists)
    timestamp_cols = [col for col in df.columns if 'time' in col.lower()]
    for col in timestamp_cols:
        try:
            df[col] = pd.to_datetime(df[col])
            df[f'{col}_hour'] = df[col].dt.hour
            df[f'{col}_dayofweek'] = df[col].dt.dayofweek
            df[f'{col}_is_weekend'] = df[f'{col}_dayofweek'].isin([5, 6]).astype(int)
        except:
            pass

    # 3. Statistical features
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    for col in numeric_cols:
        if col not in ['label', 'anomaly', 'anomaly_score']:
            # Rolling statistics (if enough data)
            if len(df) > 100:
                df[f'{col}_zscore'] = (df[col] - df[col].mean()) / df[col].std()
                df[f'{col}_rolling_mean'] = df[col].rolling(window=10, min_periods=1).mean()

    return df