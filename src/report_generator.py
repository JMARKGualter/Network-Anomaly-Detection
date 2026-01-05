import pandas as pd
import numpy as np
from datetime import datetime


def generate_report(data, anomaly_results=None):
    """Generate comprehensive report"""

    report = []
    report.append("=" * 60)
    report.append("NETWORK ANOMALY DETECTION REPORT")
    report.append("=" * 60)
    report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("")

    # Section 1: Dataset Overview
    report.append("1. DATASET OVERVIEW")
    report.append("-" * 40)
    report.append(f"Total samples: {len(data):,}")
    report.append(f"Total features: {len(data.columns)}")
    report.append(f"Dataset shape: {data.shape}")
    report.append("")

    # Section 2: Data Types
    report.append("2. DATA TYPES")
    report.append("-" * 40)
    type_counts = data.dtypes.value_counts()
    for dtype, count in type_counts.items():
        report.append(f"{dtype}: {count} columns")
    report.append("")

    # Section 3: Missing Values
    report.append("3. MISSING VALUES")
    report.append("-" * 40)
    missing = data.isnull().sum()
    missing_pct = (missing / len(data)) * 100

    for col in missing[missing > 0].index:
        report.append(f"{col}: {missing[col]:,} ({missing_pct[col]:.1f}%)")

    if missing.sum() == 0:
        report.append("No missing values found")
    report.append("")

    # Section 4: Basic Statistics
    report.append("4. BASIC STATISTICS")
    report.append("-" * 40)
    numeric_cols = data.select_dtypes(include=[np.number]).columns

    for col in numeric_cols[:5]:  # First 5 numeric columns
        report.append(f"{col}:")
        report.append(f"  Mean: {data[col].mean():.2f}")
        report.append(f"  Std:  {data[col].std():.2f}")
        report.append(f"  Min:  {data[col].min():.2f}")
        report.append(f"  25%:  {data[col].quantile(0.25):.2f}")
        report.append(f"  50%:  {data[col].quantile(0.50):.2f}")
        report.append(f"  75%:  {data[col].quantile(0.75):.2f}")
        report.append(f"  Max:  {data[col].max():.2f}")
        report.append("")

    # Section 5: Anomaly Detection Results
    if anomaly_results is not None and 'anomaly' in anomaly_results.columns:
        report.append("5. ANOMALY DETECTION RESULTS")
        report.append("-" * 40)

        anomaly_count = (anomaly_results['anomaly'] == 1).sum()
        normal_count = (anomaly_results['anomaly'] == 0).sum()

        report.append(f"Total anomalies detected: {anomaly_count:,}")
        report.append(f"Normal samples: {normal_count:,}")
        report.append(f"Anomaly percentage: {anomaly_count / len(anomaly_results) * 100:.2f}%")
        report.append("")

        # Top anomalous features
        if 'anomaly_score' in anomaly_results.columns:
            top_anomalies = anomaly_results.nlargest(5, 'anomaly_score')
            report.append("Top 5 anomalies (by score):")
            for idx, row in top_anomalies.iterrows():
                report.append(f"  Row {idx}: Score = {row['anomaly_score']:.4f}")
            report.append("")

        # Anomaly types if available
        if 'anomaly_type' in anomaly_results.columns:
            type_counts = anomaly_results[anomaly_results['anomaly'] == 1]['anomaly_type'].value_counts()
            if len(type_counts) > 0:
                report.append("Anomaly types:")
                for anomaly_type, count in type_counts.items():
                    report.append(f"  {anomaly_type}: {count}")
                report.append("")

    # Section 6: Recommendations
    report.append("6. RECOMMENDATIONS")
    report.append("-" * 40)

    if anomaly_results is not None and 'anomaly' in anomaly_results.columns:
        anomaly_count = (anomaly_results['anomaly'] == 1).sum()

        if anomaly_count > 0:
            report.append("⚠️  ACTION REQUIRED:")
            report.append(f"- Investigate {anomaly_count} detected anomalies")
            report.append("- Review network traffic during anomaly periods")
            report.append("- Check for potential security breaches")
            report.append("- Monitor affected IP addresses/protocols")
        else:
            report.append("✅  NO IMMEDIATE ACTION NEEDED:")
            report.append("- No anomalies detected in current data")
            report.append("- Continue regular monitoring")
    else:
        report.append("📊  NEXT STEPS:")
        report.append("- Run anomaly detection on the data")
        report.append("- Review basic statistics for unusual patterns")
        report.append("- Consider segmenting data by protocol/time")

    report.append("")

    # Section 7: Technical Details
    report.append("7. TECHNICAL DETAILS")
    report.append("-" * 40)
    report.append(f"Analysis timestamp: {datetime.now().isoformat()}")
    report.append(f"Data file size: {data.memory_usage(deep=True).sum() / 1024:.1f} KB")
    report.append(f"Unique values in key columns:")

    # Show unique counts for some columns
    for col in data.columns[:3]:  # First 3 columns
        unique_count = data[col].nunique()
        report.append(f"  {col}: {unique_count:,} unique values")

    report.append("")
    report.append("=" * 60)
    report.append("END OF REPORT")
    report.append("=" * 60)

    return "\n".join(report)


def export_report_to_file(report_text, filename):
    """Export report to file"""
    with open(filename, 'w') as f:
        f.write(report_text)

    return filename