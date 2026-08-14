import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')


class SimplifiedAnomalyDetector:
    """Simple, consumer-friendly anomaly detection"""
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.model = None
    
    def detect(self, df, contamination=0.1):
        """
        Detect anomalies in network data
        Returns: DataFrame with 'anomaly' column (1 = issue, 0 = normal)
        """
        # Prepare features
        X = self.prepare_features(df)
        
        # Use Isolation Forest (works well without tuning)
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=42
        )
        
        # Predict
        predictions = self.model.fit_predict(X)
        scores = self.model.decision_function(X)
        
        # Convert to simple format: 1 = issue, 0 = normal
        anomaly_labels = np.where(predictions == -1, 1, 0)
        
        # Add results to dataframe
        result_df = df.copy()
        result_df['anomaly'] = anomaly_labels
        result_df['anomaly_score'] = scores
        
        return result_df
    
    def prepare_features(self, df):
        """Prepare features for detection"""
        # Select numeric columns
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        
        # Remove obvious non-feature columns
        exclude = ['label', 'target', 'class', 'is_anomaly']
        feature_cols = [col for col in numeric_cols if col not in exclude]
        
        if len(feature_cols) == 0:
            # If no numeric columns, use index as feature
            X = np.array(range(len(df))).reshape(-1, 1)
            return self.scaler.fit_transform(X)
        
        X = df[feature_cols].copy()
        
        # Handle missing values
        X = X.fillna(X.median())
        
        # Scale
        X_scaled = self.scaler.fit_transform(X)
        
        return X_scaled
    
    def get_simple_explanation(self, df, row_index):
        """Get simple explanation for an anomaly"""
        if 'anomaly' not in df.columns:
            return "No anomaly data available"
        
        if df.loc[row_index, 'anomaly'] == 0:
            return "This record appears normal"
        
        # Find what's unusual
        row = df.loc[row_index]
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        
        explanations = []
        
        for col in numeric_cols[:5]:  # Check first 5 numeric columns
            val = row[col]
            mean = df[col].mean()
            std = df[col].std()
            
            if std > 0 and abs(val - mean) > 2 * std:
                diff = abs(val - mean) / std
                direction = "higher" if val > mean else "lower"
                explanations.append(f"• {col} is {diff:.1f} std dev {direction} than normal")
        
        if explanations:
            return "Possible issue detected:\n" + "\n".join(explanations)
        else:
            return "Unusual pattern detected (review details for more information)"


class AnomalyExplainer:
    """Simple explanations for anomalies"""
    
    @staticmethod
    def explain_issue(row, df):
        """Get human-readable explanation"""
        explanations = []
        
        # Check numeric values
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        
        for col in numeric_cols[:5]:
            val = row[col]
            mean = df[col].mean()
            std = df[col].std()
            
            if std > 0 and abs(val - mean) > 2 * std:
                direction = "above" if val > mean else "below"
                explanations.append(f"{col}: {val:.1f} ({direction} normal)")
        
        return "\n".join(explanations) if explanations else "No obvious explanation found"