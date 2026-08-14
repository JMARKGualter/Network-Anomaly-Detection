import matplotlib.pyplot as plt
import numpy as np


def create_simple_visualizations(df, anomaly_results=None):
    """Create simple, consumer-friendly visualizations"""
    
    figures = {}
    
    # 1. Health meter
    if anomaly_results is not None:
        fig = create_health_gauge(anomaly_results)
        figures['health'] = fig
    
    # 2. Simple activity chart
    fig = create_activity_chart(df, anomaly_results)
    figures['activity'] = fig
    
    # 3. Issue summary
    if anomaly_results is not None:
        fig = create_issue_summary(anomaly_results)
        figures['issues'] = fig
    
    return figures


def create_health_gauge(anomaly_results):
    """Create a simple health gauge"""
    fig, ax = plt.subplots(figsize=(4, 4))
    
    anomaly_pct = anomaly_results['anomaly'].sum() / len(anomaly_results) * 100
    health_score = 100 - anomaly_pct
    
    # Simple bar
    colors = ['#fc8181' if health_score < 50 else '#ed8936' if health_score < 80 else '#48bb78']
    
    ax.barh(['Health'], [health_score], color=colors[0], height=0.5)
    ax.set_xlim(0, 100)
    ax.set_xlabel('Health Score (%)')
    ax.set_title(f'Network Health: {health_score:.0f}%')
    
    # Remove spines
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_visible(False)
    
    fig.tight_layout()
    return fig


def create_activity_chart(df, anomaly_results=None):
    """Create simple activity chart"""
    fig, ax = plt.subplots(figsize=(8, 4))
    
    # Use first numeric column
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    if len(numeric_cols) == 0:
        ax.text(0.5, 0.5, 'No numeric data to display', 
                ha='center', va='center', transform=ax.transAxes)
        return fig
    
    col = numeric_cols[0]
    data_sample = df[col].head(200)
    
    ax.plot(range(len(data_sample)), data_sample, color='#4299e1', alpha=0.7)
    
    # Highlight anomalies
    if anomaly_results is not None and 'anomaly' in anomaly_results.columns:
        anomalies = anomaly_results[anomaly_results['anomaly'] == 1]
        anomaly_indices = anomalies.index[:100]
        if len(anomaly_indices) > 0:
            anomaly_values = anomalies[col].head(100)
            ax.scatter(anomaly_indices, anomaly_values, 
                      color='#fc8181', s=50, zorder=5)
    
    ax.set_xlabel('Data Point')
    ax.set_ylabel(col)
    ax.set_title('Network Activity')
    ax.grid(True, alpha=0.3)
    
    fig.tight_layout()
    return fig


def create_issue_summary(anomaly_results):
    """Create a simple issue summary chart"""
    fig, ax = plt.subplots(figsize=(6, 4))
    
    issue_count = anomaly_results['anomaly'].sum()
    normal_count = len(anomaly_results) - issue_count
    
    ax.pie([normal_count, issue_count], 
           labels=['Normal', 'Issues'],
           colors=['#48bb78', '#fc8181'],
           autopct='%1.1f%%',
           startangle=90)
    
    ax.set_title('Network Health Summary')
    
    fig.tight_layout()
    return fig