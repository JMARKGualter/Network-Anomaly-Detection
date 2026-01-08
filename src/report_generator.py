import pandas as pd
import numpy as np
from datetime import datetime
import json
import os
from datetime import timedelta


class ReportGenerator:
    """Generate comprehensive network analysis reports"""

    def __init__(self):
        self.report_sections = []
        self.stats = {}

    def generate_comprehensive_report(self, data, anomaly_results=None, analysis_type="full"):
        """
        Generate a complete network analysis report

        Parameters:
        -----------
        data : pd.DataFrame
            Original network data
        anomaly_results : pd.DataFrame
            Results from anomaly detection
        analysis_type : str
            "full", "executive", "technical", or "security"

        Returns:
        --------
        str : Complete report text
        """

        self.report_sections = []
        self.stats = self._calculate_statistics(data, anomaly_results)

        # Header
        self._add_header()

        # Executive Summary (always included)
        self._add_executive_summary()

        # Detailed sections based on analysis type
        if analysis_type in ["full", "technical"]:
            self._add_data_overview(data)
            self._add_traffic_analysis(data)
            self._add_protocol_analysis(data)

        if anomaly_results is not None:
            if analysis_type in ["full", "security", "technical"]:
                self._add_anomaly_detection_results(anomaly_results)
                self._add_threat_analysis(anomaly_results, data)

        if analysis_type in ["full", "technical"]:
            self._add_performance_metrics(data)
            self._add_statistical_analysis(data)

        # Recommendations
        self._add_recommendations()

        # Appendices
        if analysis_type == "full":
            self._add_appendix(data)

        # Footer
        self._add_footer()

        return "\n".join(self.report_sections)

    def _calculate_statistics(self, data, anomaly_results):
        """Calculate comprehensive statistics"""
        stats = {
            'report_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'data_points': len(data),
            'features': len(data.columns),
            'time_range': None,
            'unique_ips': 0,
            'protocols': [],
            'total_traffic': 0,
            'anomaly_count': 0,
            'anomaly_rate': 0,
        }

        # Time range
        time_cols = [col for col in data.columns
                     if any(keyword in col.lower()
                            for keyword in ['time', 'timestamp', 'date'])]
        if time_cols:
            try:
                times = pd.to_datetime(data[time_cols[0]], errors='coerce')
                stats['time_range'] = f"{times.min()} to {times.max()}"
            except:
                pass

        # IP statistics
        ip_cols = [col for col in data.columns
                   if any(keyword in col.lower()
                          for keyword in ['ip', 'src', 'dst', 'addr'])]
        if ip_cols:
            unique_ips = set()
            for col in ip_cols:
                unique_ips.update(data[col].dropna().astype(str).unique())
            stats['unique_ips'] = len(unique_ips)

        # Protocol statistics
        protocol_cols = [col for col in data.columns
                         if any(keyword in col.lower()
                                for keyword in ['proto', 'protocol', 'type'])]
        if protocol_cols:
            protocol_col = protocol_cols[0]
            top_protocols = data[protocol_col].value_counts().head(5)
            stats['protocols'] = list(top_protocols.items())

        # Traffic volume
        size_cols = [col for col in data.columns
                     if any(keyword in col.lower()
                            for keyword in ['size', 'length', 'bytes'])]
        if size_cols:
            stats['total_traffic'] = data[size_cols[0]].sum()

        # Anomaly statistics
        if anomaly_results is not None and 'anomaly' in anomaly_results.columns:
            stats['anomaly_count'] = (anomaly_results['anomaly'] == 1).sum()
            stats['anomaly_rate'] = stats['anomaly_count'] / len(anomaly_results) * 100

        return stats

    def _add_header(self):
        """Add report header"""
        header = [
            "=" * 70,
            "NETWORK ANALYSIS & ANOMALY DETECTION REPORT",
            "=" * 70,
            f"Generated: {self.stats['report_date']}",
            f"Report ID: NA-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "",
        ]
        self.report_sections.extend(header)

    def _add_executive_summary(self):
        """Add executive summary section"""
        summary = [
            "1. EXECUTIVE SUMMARY",
            "-" * 40,
            "",
        ]

        # Network health assessment
        if self.stats['anomaly_rate'] < 1:
            health_status = "✅ EXCELLENT"
            health_desc = "Network operating normally with minimal anomalies."
        elif self.stats['anomaly_rate'] < 5:
            health_status = "⚠️  GOOD"
            health_desc = "Minor anomalies detected, recommend monitoring."
        elif self.stats['anomaly_rate'] < 10:
            health_status = "🔶 FAIR"
            health_desc = "Moderate anomalies present, investigation recommended."
        else:
            health_status = "🔴 POOR"
            health_desc = "High anomaly rate, immediate attention required."

        summary.extend([
            f"Network Health: {health_status}",
            f"Assessment: {health_desc}",
            "",
            "KEY FINDINGS:",
            f"- Analyzed {self.stats['data_points']:,} network events",
            f"- Monitored {self.stats['unique_ips']:,} unique IP addresses",
            f"- Detected {self.stats['anomaly_count']:,} anomalies ({self.stats['anomaly_rate']:.1f}%)",
            "",
        ])

        # Time range if available
        if self.stats['time_range']:
            summary.append(f"Analysis Period: {self.stats['time_range']}")

        summary.append("")
        self.report_sections.extend(summary)

    def _add_data_overview(self, data):
        """Add data overview section"""
        overview = [
            "2. DATA OVERVIEW",
            "-" * 40,
            "",
            f"Dataset Size: {self.stats['data_points']:,} records × {self.stats['features']} features",
            f"Memory Usage: {data.memory_usage(deep=True).sum() / 1024 / 1024:.2f} MB",
            "",
            "DATA QUALITY:",
        ]

        # Missing values analysis
        missing = data.isnull().sum()
        missing_pct = (missing / len(data)) * 100

        if missing.sum() > 0:
            overview.append("Missing Values:")
            for col in missing[missing > 0].index:
                overview.append(f"  • {col}: {missing[col]:,} ({missing_pct[col]:.1f}%)")
        else:
            overview.append("  ✅ No missing values detected")

        # Data types
        overview.append("")
        overview.append("DATA TYPES:")
        for dtype in data.dtypes.unique():
            count = (data.dtypes == dtype).sum()
            overview.append(f"  • {dtype}: {count} columns")

        overview.append("")
        self.report_sections.extend(overview)

    def _add_traffic_analysis(self, data):
        """Add traffic analysis section"""
        traffic = [
            "3. TRAFFIC ANALYSIS",
            "-" * 40,
            "",
        ]

        # Time-based patterns
        time_cols = [col for col in data.columns
                     if any(keyword in col.lower()
                            for keyword in ['time', 'timestamp'])]

        if time_cols and len(data) > 0:
            try:
                times = pd.to_datetime(data[time_cols[0]], errors='coerce')
                traffic.append("TEMPORAL PATTERNS:")
                traffic.append(f"  • Analysis period: {times.min().strftime('%Y-%m-%d %H:%M')} to "
                               f"{times.max().strftime('%Y-%m-%d %H:%M')}")
                traffic.append(f"  • Duration: {times.max() - times.min()}")

                # Hourly distribution
                if len(times.dropna()) > 0:
                    hours = times.dt.hour
                    peak_hour = hours.mode()[0] if not hours.mode().empty else 'N/A'
                    traffic.append(f"  • Peak traffic hour: {peak_hour}:00")
            except:
                pass

        # Traffic volume
        size_cols = [col for col in data.columns
                     if any(keyword in col.lower()
                            for keyword in ['size', 'length', 'bytes'])]

        if size_cols:
            size_col = size_cols[0]
            traffic.append("")
            traffic.append("TRAFFIC VOLUME:")
            traffic.append(f"  • Total: {self.stats['total_traffic']:,.0f} bytes")
            traffic.append(f"  • Average packet size: {data[size_col].mean():.0f} bytes")
            traffic.append(f"  • Maximum packet size: {data[size_col].max():.0f} bytes")
            traffic.append(f"  • Minimum packet size: {data[size_col].min():.0f} bytes")

        traffic.append("")
        self.report_sections.extend(traffic)

    def _add_protocol_analysis(self, data):
        """Add protocol analysis section"""
        protocol = [
            "4. PROTOCOL ANALYSIS",
            "-" * 40,
            "",
        ]

        protocol_cols = [col for col in data.columns
                         if any(keyword in col.lower()
                                for keyword in ['proto', 'protocol', 'type'])]

        if protocol_cols:
            protocol_col = protocol_cols[0]
            protocol_counts = data[protocol_col].value_counts()

            protocol.append("PROTOCOL DISTRIBUTION:")
            total = protocol_counts.sum()
            for proto, count in protocol_counts.head(10).items():
                percentage = (count / total) * 100
                protocol.append(f"  • {proto}: {count:,} ({percentage:.1f}%)")

            # Protocol insights
            if len(protocol_counts) > 0:
                most_common = protocol_counts.index[0]
                least_common = protocol_counts.index[-1]
                protocol.append("")
                protocol.append("PROTOCOL INSIGHTS:")
                protocol.append(f"  • Most common: {most_common} ({protocol_counts.iloc[0]:,} packets)")
                protocol.append(f"  • Least common: {least_common} ({protocol_counts.iloc[-1]:,} packets)")
                protocol.append(f"  • Diversity: {len(protocol_counts)} unique protocols")
        else:
            protocol.append("⚠️ No protocol information found in dataset")

        protocol.append("")
        self.report_sections.extend(protocol)

    def _add_anomaly_detection_results(self, anomaly_results):
        """Add anomaly detection results section"""
        anomalies = [
            "5. ANOMALY DETECTION RESULTS",
            "-" * 40,
            "",
        ]

        if 'anomaly' not in anomaly_results.columns:
            anomalies.append("⚠️ No anomaly detection results available")
            self.report_sections.extend(anomalies)
            return

        anomaly_count = self.stats['anomaly_count']
        normal_count = len(anomaly_results) - anomaly_count

        anomalies.extend([
            "DETECTION SUMMARY:",
            f"• Total samples analyzed: {len(anomaly_results):,}",
            f"• Anomalies detected: {anomaly_count:,}",
            f"• Normal traffic: {normal_count:,}",
            f"• Anomaly rate: {self.stats['anomaly_rate']:.1f}%",
            "",
        ])

        # Severity analysis if scores available
        if 'anomaly_score' in anomaly_results.columns:
            scores = anomaly_results[anomaly_results['anomaly'] == 1]['anomaly_score']
            if len(scores) > 0:
                anomalies.append("ANOMALY SEVERITY:")
                anomalies.append(f"  • Average severity score: {scores.mean():.3f}")
                anomalies.append(f"  • Minimum score: {scores.min():.3f}")
                anomalies.append(f"  • Maximum score: {scores.max():.3f}")

                # Categorize by severity
                if len(scores) > 0:
                    high = (scores > scores.quantile(0.75)).sum()
                    medium = ((scores > scores.quantile(0.25)) & (scores <= scores.quantile(0.75))).sum()
                    low = (scores <= scores.quantile(0.25)).sum()

                    anomalies.append("")
                    anomalies.append("SEVERITY DISTRIBUTION:")
                    anomalies.append(f"  • High severity: {high} anomalies")
                    anomalies.append(f"  • Medium severity: {medium} anomalies")
                    anomalies.append(f"  • Low severity: {low} anomalies")

        # Top anomalies
        if anomaly_count > 0:
            anomalies.append("")
            anomalies.append("TOP ANOMALIES (by severity):")

            # Get top 5 anomalies
            top_anomalies = anomaly_results[anomaly_results['anomaly'] == 1]
            if 'anomaly_score' in top_anomalies.columns:
                top_anomalies = top_anomalies.nlargest(5, 'anomaly_score')

            for idx, (_, row) in enumerate(top_anomalies.head(5).iterrows(), 1):
                anomalies.append(f"{idx}. Anomaly at index {row.name}")
                if 'anomaly_score' in row:
                    anomalies.append(f"   Severity: {row['anomaly_score']:.3f}")

        anomalies.append("")
        self.report_sections.extend(anomalies)

    def _add_threat_analysis(self, anomaly_results, data):
        """Add threat analysis section"""
        threats = [
            "6. THREAT ANALYSIS",
            "-" * 40,
            "",
        ]

        if self.stats['anomaly_count'] == 0:
            threats.append("✅ NO THREATS DETECTED")
            threats.append("Network appears secure with no suspicious activities.")
            self.report_sections.extend(threats)
            return

        # Try to categorize threats
        threat_categories = self._categorize_threats(anomaly_results, data)

        if threat_categories:
            threats.append("DETECTED THREAT CATEGORIES:")
            for category, count in threat_categories.items():
                threats.append(f"  • {category}: {count} occurrences")
        else:
            threats.append("⚠️ Generic anomalies detected (unable to categorize)")

        # Security recommendations
        threats.append("")
        threats.append("SECURITY ASSESSMENT:")

        if self.stats['anomaly_rate'] < 2:
            threats.append("  ✅ LOW RISK: Network security appears adequate")
            threats.append("  Recommendation: Continue regular monitoring")
        elif self.stats['anomaly_rate'] < 10:
            threats.append("  ⚠️  MODERATE RISK: Some suspicious activities detected")
            threats.append("  Recommendation: Investigate anomalies and review logs")
        else:
            threats.append("  🔴 HIGH RISK: Significant anomalies detected")
            threats.append("  Recommendation: Immediate investigation required")

        threats.append("")
        self.report_sections.extend(threats)

    def _categorize_threats(self, anomaly_results, data):
        """Categorize detected threats"""
        categories = {}

        if self.stats['anomaly_count'] == 0:
            return categories

        # Get anomaly samples
        anomalies = anomaly_results[anomaly_results['anomaly'] == 1]

        # Check for common threat patterns
        # 1. Port scans (many connections to different ports)
        port_cols = [col for col in data.columns
                     if any(keyword in col.lower()
                            for keyword in ['port', 'dstport'])]

        if port_cols and len(anomalies) > 10:
            # Simple heuristic: if anomalies have diverse ports
            unique_ports = anomalies[port_cols[0]].nunique()
            if unique_ports > len(anomalies) * 0.5:
                categories['Port Scanning'] = unique_ports

        # 2. DDoS/Flood (high packet rate)
        time_cols = [col for col in data.columns
                     if any(keyword in col.lower()
                            for keyword in ['time', 'timestamp'])]

        if time_cols and len(anomalies) > 20:
            try:
                times = pd.to_datetime(anomalies[time_cols[0]], errors='coerce')
                time_diff = times.diff().dt.total_seconds()
                avg_rate = 1 / time_diff.mean() if time_diff.mean() > 0 else 0

                if avg_rate > 100:  # More than 100 packets per second
                    categories['High Volume Traffic'] = len(anomalies)
            except:
                pass

        # 3. Large packet anomalies
        size_cols = [col for col in data.columns
                     if any(keyword in col.lower()
                            for keyword in ['size', 'length'])]

        if size_cols:
            avg_size = data[size_cols[0]].mean()
            large_packets = anomalies[anomalies[size_cols[0]] > avg_size * 3]
            if len(large_packets) > 0:
                categories['Oversized Packets'] = len(large_packets)

        return categories

    def _add_performance_metrics(self, data):
        """Add performance metrics section"""
        performance = [
            "7. PERFORMANCE METRICS",
            "-" * 40,
            "",
        ]

        # Network performance indicators
        metrics = []

        # Latency if available
        latency_cols = [col for col in data.columns
                        if any(keyword in col.lower()
                               for keyword in ['rtt', 'latency', 'delay'])]

        if latency_cols:
            latency = data[latency_cols[0]].dropna()
            if len(latency) > 0:
                metrics.extend([
                    f"Average Latency: {latency.mean():.1f} ms",
                    f"Latency Std Dev: {latency.std():.1f} ms",
                    f"Maximum Latency: {latency.max():.1f} ms",
                    f"95th Percentile: {latency.quantile(0.95):.1f} ms",
                ])

        # Throughput if available
        throughput_cols = [col for col in data.columns
                           if any(keyword in col.lower()
                                  for keyword in ['throughput', 'rate', 'speed'])]

        if throughput_cols:
            throughput = data[throughput_cols[0]].dropna()
            if len(throughput) > 0:
                metrics.extend([
                    f"Average Throughput: {throughput.mean():.1f} Mbps",
                    f"Peak Throughput: {throughput.max():.1f} Mbps",
                ])

        if metrics:
            performance.extend(metrics)
        else:
            performance.append("⚠️ No performance metrics available in dataset")

        performance.append("")
        self.report_sections.extend(performance)

    def _add_statistical_analysis(self, data):
        """Add statistical analysis section"""
        stats = [
            "8. STATISTICAL ANALYSIS",
            "-" * 40,
            "",
        ]

        numeric_cols = data.select_dtypes(include=[np.number]).columns

        if len(numeric_cols) > 0:
            stats.append("KEY STATISTICS:")

            for col in numeric_cols[:3]:  # First 3 numeric columns
                stats.append(f"\n{col}:")
                stats.append(f"  • Mean: {data[col].mean():.2f}")
                stats.append(f"  • Std Dev: {data[col].std():.2f}")
                stats.append(f"  • Min: {data[col].min():.2f}")
                stats.append(f"  • 25%: {data[col].quantile(0.25):.2f}")
                stats.append(f"  • 50% (Median): {data[col].quantile(0.50):.2f}")
                stats.append(f"  • 75%: {data[col].quantile(0.75):.2f}")
                stats.append(f"  • Max: {data[col].max():.2f}")
                stats.append(f"  • Skewness: {data[col].skew():.3f}")
                stats.append(f"  • Kurtosis: {data[col].kurtosis():.3f}")
        else:
            stats.append("⚠️ No numeric columns for statistical analysis")

        stats.append("")
        self.report_sections.extend(stats)

    def _add_recommendations(self):
        """Add recommendations section"""
        recommendations = [
            "9. RECOMMENDATIONS & ACTION ITEMS",
            "-" * 40,
            "",
        ]

        # Risk-based recommendations
        if self.stats['anomaly_rate'] == 0:
            recommendations.extend([
                "✅ NETWORK HEALTHY",
                "   No immediate action required.",
                "",
                "MAINTENANCE RECOMMENDATIONS:",
                "1. Continue regular monitoring schedule",
                "2. Update firewall rules quarterly",
                "3. Review access controls biannually",
                "4. Conduct security audit annually",
            ])

        elif self.stats['anomaly_rate'] < 5:
            recommendations.extend([
                "⚠️  MINOR ISSUES DETECTED",
                "   Proactive measures recommended.",
                "",
                "IMMEDIATE ACTIONS (Within 7 days):",
                "1. Review detected anomalies",
                "2. Check firewall logs for suspicious patterns",
                "3. Verify user access permissions",
                "",
                "PREVENTIVE MEASURES:",
                "1. Implement stricter access controls",
                "2. Set up automated alerting for similar patterns",
                "3. Schedule network traffic baseline review",
            ])

        else:
            recommendations.extend([
                "🔴 SIGNIFICANT ANOMALIES DETECTED",
                "   Immediate investigation required.",
                "",
                "URGENT ACTIONS (Within 24 hours):",
                f"1. Investigate {self.stats['anomaly_count']:,} detected anomalies",
                "2. Check for security breaches or data exfiltration",
                "3. Review network device configurations",
                "4. Isolate suspicious devices if necessary",
                "",
                "FOLLOW-UP ACTIONS:",
                "1. Conduct forensic analysis of affected systems",
                "2. Update intrusion detection signatures",
                "3. Review and update security policies",
                "4. Schedule penetration testing",
            ])

        # General recommendations
        recommendations.extend([
            "",
            "GENERAL BEST PRACTICES:",
            "1. Keep all network devices updated with latest firmware",
            "2. Implement network segmentation",
            "3. Use encrypted protocols where possible",
            "4. Maintain regular backups of configurations",
            "5. Conduct employee security awareness training",
        ])

        recommendations.append("")
        self.report_sections.extend(recommendations)

    def _add_appendix(self, data):
        """Add appendix with detailed information"""
        appendix = [
            "APPENDIX: DETAILED INFORMATION",
            "-" * 40,
            "",
            "A. DATASET COLUMNS:",
        ]

        # Column information
        for idx, (col, dtype) in enumerate(data.dtypes.items(), 1):
            appendix.append(f"{idx}. {col} ({dtype})")

            # Add sample values for first few rows
            if idx <= 5:
                sample = data[col].head(3).tolist()
                appendix.append(f"   Sample: {sample}")

        appendix.append("")
        appendix.append("B. ANALYSIS METHODOLOGY:")
        appendix.extend([
            "1. Data preprocessing included:",
            "   • Missing value imputation",
            "   • Feature normalization",
            "   • Outlier detection preprocessing",
            "",
            "2. Anomaly detection algorithms used:",
            "   • Isolation Forest (unsupervised)",
            "   • Local Outlier Factor (density-based)",
            "   • Statistical thresholding",
            "",
            "3. Validation methodology:",
            "   • Cross-validation where applicable",
            "   • Manual review of top anomalies",
            "   • Comparison with known network baselines",
        ])

        appendix.append("")
        self.report_sections.extend(appendix)

    def _add_footer(self):
        """Add report footer"""
        footer = [
            "=" * 70,
            "END OF REPORT",
            "=" * 70,
            "",
            "Report generated by: Network Anomaly Detection System",
            f"Version: 2.0 | Analysis Date: {datetime.now().strftime('%Y-%m-%d')}",
            "",
            "CONFIDENTIALITY NOTICE:",
            "This report contains sensitive network information.",
            "Distribute only to authorized personnel.",
            "",
            "For questions or further analysis, contact:",
            "Network Security Team | security@example.com",
        ]
        self.report_sections.extend(footer)

    def export_report(self, report_text, filename=None):
        """Export report to file"""
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"network_analysis_report_{timestamp}.txt"

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(report_text)

        print(f"✅ Report saved to: {filename}")
        return filename

    def generate_html_report(self, report_text):
        """Convert text report to HTML format"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
                h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
                h2 {{ color: #34495e; border-bottom: 1px solid #bdc3c7; padding-bottom: 5px; }}
                .summary {{ background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; }}
                .anomaly-high {{ color: #e74c3c; font-weight: bold; }}
                .anomaly-medium {{ color: #f39c12; }}
                .anomaly-low {{ color: #27ae60; }}
                .recommendation {{ background-color: #e8f4fc; padding: 15px; border-left: 4px solid #3498db; margin: 10px 0; }}
                table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                tr:nth-child(even) {{ background-color: #f9f9f9; }}
                .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #7f8c8d; font-size: 0.9em; }}
            </style>
        </head>
        <body>
            <h1>📊 Network Analysis Report</h1>
            <div class="summary">
                <strong>Report Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
                <strong>Analysis Period:</strong> {self.stats.get('time_range', 'N/A')}<br>
                <strong>Data Points:</strong> {self.stats['data_points']:,}<br>
                <strong>Anomalies Detected:</strong> {self.stats['anomaly_count']:,} ({self.stats['anomaly_rate']:.1f}%)
            </div>
        """

        # Convert text sections to HTML
        lines = report_text.split('\n')
        in_list = False

        for line in lines:
            if line.startswith('=' * 40):
                continue  # Skip separator lines
            elif line.startswith('#') or line.startswith('1. ') or line.startswith('2. '):
                # Convert section headers
                line = line.strip('#. 123456789')
                html += f'<h2>{line}</h2>\n'
            elif line.startswith('• ') or line.startswith('- '):
                if not in_list:
                    html += '<ul>\n'
                    in_list = True
                html += f'<li>{line[2:]}</li>\n'
            elif line.strip() == '' and in_list:
                html += '</ul>\n'
                in_list = False
            elif line.strip():
                if '✅' in line:
                    html += f'<p style="color: #27ae60;">{line}</p>\n'
                elif '⚠️' in line:
                    html += f'<p style="color: #f39c12;">{line}</p>\n'
                elif '🔴' in line:
                    html += f'<p style="color: #e74c3c;">{line}</p>\n'
                else:
                    html += f'<p>{line}</p>\n'

        html += """
            <div class="footer">
                <p>Generated by Network Anomaly Detection System v2.0</p>
                <p>Confidential - For authorized personnel only</p>
            </div>
        </body>
        </html>
        """

        return html