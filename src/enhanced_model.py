import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.cluster import DBSCAN
import warnings

warnings.filterwarnings('ignore')


class EnhancedAnomalyDetector:
    def __init__(self):
        self.models = {}
        self.scaler = StandardScaler()
        self.feature_importance = None

    def detect(self, df, model_type="Isolation Forest", contamination=0.1):
        """Enhanced anomaly detection with multiple algorithms"""

        # Prepare features
        X = self.prepare_features(df)

        if model_type == "Isolation Forest":
            results = self.isolation_forest_detection(X, contamination)

        elif model_type == "Local Outlier Factor":
            results = self.lof_detection(X, contamination)

        elif model_type == "One-Class SVM":
            results = self.oneclass_svm_detection(X, contamination)

        elif model_type == "Autoencoder":
            results = self.autoencoder_detection(X)

        elif model_type == "Ensemble Voting":
            results = self.ensemble_detection(X, contamination)

        else:
            raise ValueError(f"Unknown model type: {model_type}")

        # Add results to original dataframe
        result_df = df.copy()
        result_df['anomaly'] = results['predictions']
        result_df['anomaly_score'] = results['scores']
        result_df['anomaly_confidence'] = results.get('confidence', 0.5)

        # Add anomaly types if available
        if 'anomaly_type' in results:
            result_df['anomaly_type'] = results['anomaly_type']

        return result_df

    def prepare_features(self, df):
        """Prepare features for anomaly detection"""
        # Select numeric features
        numeric_cols = df.select_dtypes(include=[np.number]).columns

        # Remove potential target columns
        exclude_cols = ['label', 'target', 'class', 'is_anomaly']
        feature_cols = [col for col in numeric_cols
                        if col not in exclude_cols]

        X = df[feature_cols].copy()

        # Handle missing values
        X = X.fillna(X.median())

        # Scale features
        X_scaled = self.scaler.fit_transform(X)

        return X_scaled

    def isolation_forest_detection(self, X, contamination):
        """Isolation Forest for anomaly detection"""
        model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=42,
            max_samples='auto',
            bootstrap=True,
            n_jobs=-1
        )

        predictions = model.fit_predict(X)
        scores = model.decision_function(X)

        # Convert to binary (1=anomaly, 0=normal)
        predictions = np.where(predictions == -1, 1, 0)

        return {
            'predictions': predictions,
            'scores': scores,
            'model': 'Isolation Forest'
        }

    def lof_detection(self, X, contamination):
        """Local Outlier Factor for anomaly detection"""
        model = LocalOutlierFactor(
            n_neighbors=20,
            contamination=contamination,
            novelty=True,
            n_jobs=-1
        )

        predictions = model.fit_predict(X)
        scores = model.negative_outlier_factor_

        # Convert to binary (1=anomaly, 0=normal)
        predictions = np.where(predictions == -1, 1, 0)

        return {
            'predictions': predictions,
            'scores': scores,
            'model': 'Local Outlier Factor'
        }

    def oneclass_svm_detection(self, X, contamination):
        """One-Class SVM for anomaly detection"""
        model = OneClassSVM(
            nu=contamination,
            kernel="rbf",
            gamma="scale"
        )

        predictions = model.fit_predict(X)
        scores = model.decision_function(X)

        # Convert to binary (1=anomaly, 0=normal)
        predictions = np.where(predictions == -1, 1, 0)

        return {
            'predictions': predictions,
            'scores': scores,
            'model': 'One-Class SVM'
        }

    def autoencoder_detection(self, X):
        """Autoencoder for anomaly detection"""
        try:
            from tensorflow.keras.models import Model
            from tensorflow.keras.layers import Input, Dense
            from tensorflow.keras import regularizers

            # Build autoencoder
            input_dim = X.shape[1]
            encoding_dim = max(3, input_dim // 4)  # Encode to 1/4 dimensions

            input_layer = Input(shape=(input_dim,))
            encoder = Dense(encoding_dim, activation="relu",
                            activity_regularizer=regularizers.l1(10e-5))(input_layer)
            decoder = Dense(input_dim, activation="relu")(encoder)

            autoencoder = Model(inputs=input_layer, outputs=decoder)
            autoencoder.compile(optimizer='adam', loss='mse')

            # Train
            autoencoder.fit(X, X, epochs=20, batch_size=32,
                            shuffle=True, verbose=0)

            # Get reconstruction error
            reconstructions = autoencoder.predict(X)
            mse = np.mean(np.power(X - reconstructions, 2), axis=1)

            # Threshold for anomalies (top 10%)
            threshold = np.percentile(mse, 90)
            predictions = (mse > threshold).astype(int)

            return {
                'predictions': predictions,
                'scores': mse,
                'model': 'Autoencoder',
                'confidence': 1 - (mse / np.max(mse))
            }

        except ImportError:
            # Fallback to Isolation Forest if tensorflow not available
            return self.isolation_forest_detection(X, contamination=0.1)

    def ensemble_detection(self, X, contamination):
        """Ensemble of multiple detectors"""
        # Get predictions from multiple models
        results = []

        # Isolation Forest
        if_result = self.isolation_forest_detection(X, contamination)
        results.append(if_result['predictions'])

        # LOF
        lof_result = self.lof_detection(X, contamination)
        results.append(lof_result['predictions'])

        # One-Class SVM
        svm_result = self.oneclass_svm_detection(X, contamination)
        results.append(svm_result['predictions'])

        # Combine predictions (majority voting)
        ensemble_pred = np.stack(results, axis=1)
        final_predictions = np.apply_along_axis(
            lambda x: 1 if np.sum(x) >= 2 else 0,  # At least 2 models say anomaly
            axis=1,
            arr=ensemble_pred
        )

        # Combined scores (average)
        scores = (if_result['scores'] + lof_result['scores'] + svm_result['scores']) / 3

        # Detect anomaly types based on which models flagged it
        anomaly_types = []
        for i in range(len(final_predictions)):
            if final_predictions[i] == 1:
                model_flags = []
                if ensemble_pred[i, 0] == 1:
                    model_flags.append("IF")
                if ensemble_pred[i, 1] == 1:
                    model_flags.append("LOF")
                if ensemble_pred[i, 2] == 1:
                    model_flags.append("SVM")
                anomaly_types.append("+".join(model_flags))
            else:
                anomaly_types.append("Normal")

        return {
            'predictions': final_predictions,
            'scores': scores,
            'anomaly_type': anomaly_types,
            'model': 'Ensemble Voting',
            'confidence': 0.7  # Higher confidence for ensemble
        }

    def explain_anomaly(self, df, row_index):
        """Provide explanation for a specific anomaly"""
        if 'anomaly' not in df.columns:
            return "No anomaly detection results available"

        if df.loc[row_index, 'anomaly'] == 0:
            return "This is not flagged as an anomaly"

        explanation = []
        explanation.append(f"Anomaly detected at row {row_index}")

        # Get feature values
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        exclude_cols = ['anomaly', 'anomaly_score', 'anomaly_confidence', 'anomaly_type']
        feature_cols = [col for col in numeric_cols if col not in exclude_cols]

        for col in feature_cols[:5]:  # Top 5 features
            value = df.loc[row_index, col]
            mean_val = df[col].mean()
            std_val = df[col].std()

            if abs(value - mean_val) > 2 * std_val:
                direction = "above" if value > mean_val else "below"
                explanation.append(
                    f"• {col}: {value:.2f} ({direction} average by "
                    f"{abs(value - mean_val) / std_val:.1f}σ)"
                )

        if 'anomaly_type' in df.columns:
            explanation.append(f"Anomaly type: {df.loc[row_index, 'anomaly_type']}")

        return "\n".join(explanation)