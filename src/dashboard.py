# dashboard.py - With Row Control, Search & Filter
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import pandas as pd
import numpy as np
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import matplotlib.pyplot as plt
import os
from datetime import datetime
from collections import Counter
import re

# Import your modules
from data_loader import load_and_validate_csv
from enhanced_model import SimplifiedAnomalyDetector


class NetworkHealthMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Health Monitor")
        self.root.geometry("1400x900")
        self.root.configure(bg='#0a0e1a')

        # App state
        self.data = None
        self.anomaly_results = None
        self.detector = SimplifiedAnomalyDetector()
        self.ip_stats = None
        self.report_content = None
        self.filtered_anomalies = None
        self.display_count = 10  # Default rows to show
        self.search_term = ""
        self.filter_type = "All"  # All, IP, Protocol, Port

        # Color scheme
        self.colors = {
            'bg': '#0a0e1a',
            'card': '#141b2d',
            'card_border': '#1f2a42',
            'accent': '#00d4ff',
            'success': '#00ff88',
            'warning': '#ffb700',
            'danger': '#ff4757',
            'text': '#e0e6ed',
            'text_secondary': '#8892b0'
        }

        self.setup_ui()

    def setup_ui(self):
        """Setup main UI"""
        self.root.configure(bg=self.colors['bg'])
        self.main_container = tk.Frame(self.root, bg=self.colors['bg'])
        self.main_container.pack(fill='both', expand=True, padx=20, pady=20)
        self.show_welcome()

    def show_welcome(self):
        """Welcome screen"""
        self.clear_main()

        # Header
        header_frame = tk.Frame(self.main_container, bg=self.colors['bg'])
        header_frame.pack(fill='x', pady=(0, 20))

        title = tk.Label(header_frame,
                         text="🛡️ Network Health Monitor",
                         font=('Segoe UI', 38, 'bold'),
                         bg=self.colors['bg'],
                         fg=self.colors['accent'])
        title.pack()

        subtitle = tk.Label(header_frame,
                            text="Upload your network data for instant analysis",
                            font=('Segoe UI', 13),
                            bg=self.colors['bg'],
                            fg=self.colors['text_secondary'])
        subtitle.pack(pady=(5, 0))

        # Main content - Two columns
        content = tk.Frame(self.main_container, bg=self.colors['bg'])
        content.pack(fill='both', expand=True)

        # Left Column - Upload Section
        left_frame = tk.Frame(content, bg=self.colors['bg'])
        left_frame.pack(side='left', fill='both', expand=True, padx=(0, 10))

        upload_card = tk.Frame(left_frame,
                               bg=self.colors['card'],
                               relief='flat',
                               bd=1,
                               highlightbackground=self.colors['card_border'],
                               highlightthickness=1)
        upload_card.pack(fill='both', expand=True)

        upload_inner = tk.Frame(upload_card, bg=self.colors['card'])
        upload_inner.pack(expand=True, fill='both', padx=35, pady=35)

        tk.Label(upload_inner,
                 text="📁",
                 font=('Segoe UI', 56),
                 bg=self.colors['card']).pack()

        tk.Label(upload_inner,
                 text="Upload Network Data",
                 font=('Segoe UI', 20, 'bold'),
                 bg=self.colors['card'],
                 fg=self.colors['text']).pack(pady=(15, 5))

        tk.Label(upload_inner,
                 text="CSV files from Wireshark or network logs",
                 font=('Segoe UI', 11),
                 bg=self.colors['card'],
                 fg=self.colors['text_secondary']).pack()

        upload_btn = tk.Button(upload_inner,
                               text="Choose File",
                               command=self.upload_data,
                               font=('Segoe UI', 13, 'bold'),
                               bg=self.colors['accent'],
                               fg='#0a0e1a',
                               padx=45,
                               pady=14,
                               relief='flat',
                               cursor='hand2')
        upload_btn.pack(pady=25)

        self.file_label = tk.Label(upload_inner,
                                   text="No file selected",
                                   font=('Segoe UI', 10),
                                   bg=self.colors['card'],
                                   fg=self.colors['text_secondary'])
        self.file_label.pack()

        # Features
        features_frame = tk.Frame(upload_inner, bg=self.colors['card'])
        features_frame.pack(pady=(20, 0))

        features = [
            ("📊", "Health Score", "Network rating"),
            ("🌐", "IP Analysis", "Conversation insights"),
            ("🚨", "Issue Detection", "Find problems"),
            ("🔍", "Search & Filter", "Troubleshoot issues")
        ]

        for icon_text, title_text, desc in features:
            badge = tk.Frame(features_frame, bg=self.colors['card_border'], padx=10, pady=6)
            badge.pack(side='left', padx=3)

            tk.Label(badge,
                     text=f"{icon_text} {title_text}",
                     font=('Segoe UI', 9, 'bold'),
                     bg=self.colors['card_border'],
                     fg=self.colors['text']).pack()

            tk.Label(badge,
                     text=desc,
                     font=('Segoe UI', 7),
                     bg=self.colors['card_border'],
                     fg=self.colors['text_secondary']).pack()

        # Right Column - Info
        right_frame = tk.Frame(content, bg=self.colors['bg'])
        right_frame.pack(side='right', fill='both', expand=True, padx=(10, 0))

        info_card = tk.Frame(right_frame,
                             bg=self.colors['card'],
                             relief='flat',
                             bd=1,
                             highlightbackground=self.colors['card_border'],
                             highlightthickness=1)
        info_card.pack(fill='both', expand=True)

        info_inner = tk.Frame(info_card, bg=self.colors['card'])
        info_inner.pack(expand=True, fill='both', padx=25, pady=25)

        tk.Label(info_inner,
                 text="🔍 Troubleshooting Features",
                 font=('Segoe UI', 16, 'bold'),
                 bg=self.colors['card'],
                 fg=self.colors['accent']).pack(anchor='w', pady=(0, 15))

        benefits = [
            ("🔎", "Search", "Find specific IPs or patterns"),
            ("📊", "Filter", "Filter by protocol, port, etc."),
            ("📋", "Custom Rows", "Choose how many issues to show"),
            ("💾", "Export", "Save reports for analysis")
        ]

        for icon_text, title_text, desc in benefits:
            benefit = tk.Frame(info_inner, bg=self.colors['card_border'], padx=12, pady=8)
            benefit.pack(fill='x', pady=4)

            tk.Label(benefit,
                     text=f"{icon_text} {title_text}",
                     font=('Segoe UI', 11, 'bold'),
                     bg=self.colors['card_border'],
                     fg=self.colors['text']).pack(side='left')

            tk.Label(benefit,
                     text=desc,
                     font=('Segoe UI', 9),
                     bg=self.colors['card_border'],
                     fg=self.colors['text_secondary']).pack(side='right')

        tk.Label(info_inner,
                 text="💡 Tip: Search by IP to troubleshoot specific devices",
                 font=('Segoe UI', 10),
                 bg=self.colors['card'],
                 fg=self.colors['text_secondary']).pack(pady=(15, 0))

    def upload_data(self):
        """Handle file upload"""
        filepath = filedialog.askopenfilename(
            title="Select Network Data File",
            filetypes=[("CSV files", "*.csv"), ("PCAP files", "*.pcap")]
        )

        if filepath:
            try:
                self.file_label.config(text=f"Loading: {os.path.basename(filepath)}...")
                self.root.update()

                self.data = load_and_validate_csv(filepath)
                self.analyze_ip_conversations()
                self.analyze_data()
                self.filtered_anomalies = self.anomaly_results[self.anomaly_results['anomaly'] == 1].copy()
                self.show_dashboard()

            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file:\n{str(e)}")
                self.file_label.config(text="Error loading file")

    def analyze_ip_conversations(self):
        """Analyze IP conversation statistics"""
        if self.data is None:
            return

        self.ip_stats = {
            'most_active': [],
            'least_active': [],
            'total_unique_ips': 0,
            'total_conversations': 0
        }

        ip_cols = [col for col in self.data.columns
                   if any(keyword in col.lower()
                          for keyword in ['ip', 'src', 'dst', 'source', 'destination', 'addr'])]

        if not ip_cols:
            for col in self.data.columns:
                if self.data[col].dtype == 'object':
                    sample = self.data[col].dropna().head(10).astype(str)
                    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
                    if sample.str.contains(ip_pattern).any():
                        ip_cols.append(col)

        if ip_cols:
            all_ips = []
            for col in ip_cols:
                ips = self.data[col].dropna().astype(str)
                for ip in ips:
                    matches = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ip)
                    all_ips.extend(matches)

            ip_counter = Counter(all_ips)
            valid_ips = {ip: count for ip, count in ip_counter.items()
                         if ip.count('.') == 3 and not ip.startswith('0.0.0')}

            if valid_ips:
                sorted_ips = sorted(valid_ips.items(), key=lambda x: x[1], reverse=True)
                self.ip_stats['most_active'] = sorted_ips[:10]
                self.ip_stats['least_active'] = sorted_ips[-10:]
                self.ip_stats['total_unique_ips'] = len(valid_ips)
                self.ip_stats['total_conversations'] = sum(valid_ips.values())

                local_patterns = ['192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.']
                local_ips = [ip for ip in valid_ips.keys()
                             if any(ip.startswith(pattern) for pattern in local_patterns)]

                if local_ips:
                    local_counter = {ip: valid_ips[ip] for ip in local_ips}
                    self.ip_stats['local_ip'] = max(local_counter, key=local_counter.get)

    def analyze_data(self):
        """Run anomaly detection"""
        if self.data is not None:
            self.anomaly_results = self.detector.detect(self.data)
            # Initialize filtered anomalies
            self.filtered_anomalies = self.anomaly_results[self.anomaly_results['anomaly'] == 1].copy()

    def apply_filters(self):
        """Apply search and filter to anomalies"""
        if self.anomaly_results is None:
            return

        # Start with all anomalies
        filtered = self.anomaly_results[self.anomaly_results['anomaly'] == 1].copy()

        # Apply filter type
        if self.filter_type != "All" and self.search_term:
            search_lower = self.search_term.lower()

            if self.filter_type == "IP":
                # Search in IP columns
                ip_cols = [col for col in filtered.columns
                           if any(keyword in col.lower() for keyword in ['ip', 'src', 'dst', 'source', 'destination'])]
                mask = pd.Series([False] * len(filtered))
                for col in ip_cols:
                    if col in filtered.columns:
                        mask = mask | filtered[col].astype(str).str.lower().str.contains(search_lower, na=False)
                filtered = filtered[mask]

            elif self.filter_type == "Protocol":
                # Search in protocol columns
                proto_cols = [col for col in filtered.columns
                              if any(keyword in col.lower() for keyword in ['protocol', 'proto'])]
                mask = pd.Series([False] * len(filtered))
                for col in proto_cols:
                    if col in filtered.columns:
                        mask = mask | filtered[col].astype(str).str.lower().str.contains(search_lower, na=False)
                filtered = filtered[mask]

            elif self.filter_type == "Port":
                # Search in port columns
                port_cols = [col for col in filtered.columns
                             if any(keyword in col.lower() for keyword in ['port', 'srcport', 'dstport'])]
                mask = pd.Series([False] * len(filtered))
                for col in port_cols:
                    if col in filtered.columns:
                        mask = mask | filtered[col].astype(str).str.lower().str.contains(search_lower, na=False)
                filtered = filtered[mask]
        elif self.search_term and self.filter_type == "All":
            # Search in all columns
            search_lower = self.search_term.lower()
            mask = pd.Series([False] * len(filtered))
            for col in filtered.columns:
                try:
                    mask = mask | filtered[col].astype(str).str.lower().str.contains(search_lower, na=False)
                except:
                    pass
            filtered = filtered[mask]

        self.filtered_anomalies = filtered
        self.update_issues_display()

    def update_issues_display(self):
        """Update the issues display with current filters"""
        if hasattr(self, 'issues_container'):
            # Clear existing issues display
            for widget in self.issues_container.winfo_children():
                widget.destroy()
            self.show_filtered_issues(self.issues_container)

    def show_dashboard(self):
        """Dashboard with search and filter features"""
        self.clear_main()

        if self.anomaly_results is None:
            self.show_welcome()
            return

        # Calculate stats
        anomaly_count = self.anomaly_results['anomaly'].sum()
        total_records = len(self.data)
        health_score = 100 - (anomaly_count / total_records * 100)

        # Status
        if health_score >= 85:
            status = "Excellent"
            status_color = self.colors['success']
            status_icon = "✅"
        elif health_score >= 60:
            status = "Fair"
            status_color = self.colors['warning']
            status_icon = "⚠️"
        else:
            status = "Needs Attention"
            status_color = self.colors['danger']
            status_icon = "🔴"

        # Navigation
        nav_frame = tk.Frame(self.main_container, bg=self.colors['bg'])
        nav_frame.pack(fill='x', pady=(0, 15))

        tk.Button(nav_frame,
                  text="← Upload New File",
                  command=self.show_welcome,
                  font=('Segoe UI', 10),
                  bg=self.colors['bg'],
                  fg=self.colors['text_secondary'],
                  relief='flat',
                  cursor='hand2').pack(side='left')

        tk.Label(nav_frame,
                 text="Dashboard",
                 font=('Segoe UI', 18, 'bold'),
                 bg=self.colors['bg'],
                 fg=self.colors['text']).pack(side='left', padx=(20, 0))

        # Health Score Card
        score_card = tk.Frame(self.main_container,
                              bg=self.colors['card'],
                              relief='flat',
                              bd=1,
                              highlightbackground=self.colors['card_border'],
                              highlightthickness=1)
        score_card.pack(fill='x', pady=(0, 15))

        score_inner = tk.Frame(score_card, bg=self.colors['card'])
        score_inner.pack(fill='x', padx=25, pady=20)

        # Score
        score_frame = tk.Frame(score_inner, bg=self.colors['card'])
        score_frame.pack(side='left')

        tk.Label(score_frame,
                 text=f"{health_score:.0f}%",
                 font=('Segoe UI', 52, 'bold'),
                 bg=self.colors['card'],
                 fg=status_color).pack(side='left', padx=(0, 20))

        status_frame = tk.Frame(score_frame, bg=self.colors['card'])
        status_frame.pack(side='left')

        tk.Label(status_frame,
                 text=f"{status_icon} {status}",
                 font=('Segoe UI', 20, 'bold'),
                 bg=self.colors['card'],
                 fg=status_color).pack(anchor='w')

        tk.Label(status_frame,
                 text=f"{total_records:,} records | {anomaly_count:,} issues",
                 font=('Segoe UI', 11),
                 bg=self.colors['card'],
                 fg=self.colors['text_secondary']).pack(anchor='w')

        # Stats
        stats_frame = tk.Frame(score_inner, bg=self.colors['card'])
        stats_frame.pack(side='right')

        stats_data = [
            ("📊", f"{total_records:,}", "Records"),
            ("🚨", f"{anomaly_count:,}", "Issues"),
            ("🌐", f"{self.ip_stats.get('total_unique_ips', 0):,}", "Unique IPs"),
            ("📈", f"{anomaly_count / total_records * 100:.1f}%", "Issue Rate")
        ]

        for icon_text, value, label in stats_data:
            stat_card = tk.Frame(stats_frame, bg=self.colors['card_border'], padx=12, pady=6)
            stat_card.pack(side='left', padx=4)

            tk.Label(stat_card,
                     text=f"{icon_text} {value}",
                     font=('Segoe UI', 13, 'bold'),
                     bg=self.colors['card_border'],
                     fg=self.colors['text']).pack()

            tk.Label(stat_card,
                     text=label,
                     font=('Segoe UI', 9),
                     bg=self.colors['card_border'],
                     fg=self.colors['text_secondary']).pack()

        # Main content
        main_grid = tk.Frame(self.main_container, bg=self.colors['bg'])
        main_grid.pack(fill='both', expand=True)

        # Left column - Charts
        left_col = tk.Frame(main_grid, bg=self.colors['bg'])
        left_col.pack(side='left', fill='both', expand=True, padx=(0, 10))

        # Pie Chart
        pie_card = tk.Frame(left_col,
                            bg=self.colors['card'],
                            relief='flat',
                            bd=1,
                            highlightbackground=self.colors['card_border'],
                            highlightthickness=1)
        pie_card.pack(fill='both', expand=True, pady=(0, 10))

        pie_inner = tk.Frame(pie_card, bg=self.colors['card'])
        pie_inner.pack(fill='both', expand=True, padx=15, pady=15)

        fig1 = Figure(figsize=(5, 4), facecolor=self.colors['card'])
        ax1 = fig1.add_subplot(111)
        ax1.set_facecolor(self.colors['card'])

        normal_count = total_records - anomaly_count
        pie_data = [normal_count, anomaly_count]
        pie_labels = ['Normal', 'Issues']
        pie_colors = [self.colors['success'], self.colors['danger']]

        ax1.pie(pie_data, labels=pie_labels, colors=pie_colors,
                autopct=lambda pct: f'{pct:.1f}%',
                startangle=90, explode=(0.05, 0.08),
                shadow=True, textprops={'fontsize': 10, 'color': 'white'})

        ax1.set_title(f'Network Health: {health_score:.0f}%',
                      color=self.colors['text'], fontsize=14, fontweight='bold')

        canvas1 = FigureCanvasTkAgg(fig1, pie_inner)
        canvas1.draw()
        canvas1.get_tk_widget().pack(fill='both', expand=True)

        # Line Chart
        line_card = tk.Frame(left_col,
                             bg=self.colors['card'],
                             relief='flat',
                             bd=1,
                             highlightbackground=self.colors['card_border'],
                             highlightthickness=1)
        line_card.pack(fill='both', expand=True)

        line_inner = tk.Frame(line_card, bg=self.colors['card'])
        line_inner.pack(fill='both', expand=True, padx=15, pady=15)

        fig2 = Figure(figsize=(5, 3), facecolor=self.colors['card'])
        ax2 = fig2.add_subplot(111)
        ax2.set_facecolor(self.colors['card'])

        numeric_cols = self.data.select_dtypes(include=[np.number]).columns
        if len(numeric_cols) > 0:
            col = numeric_cols[0]
            data_sample = self.data[col].head(200).values

            ax2.plot(range(len(data_sample)), data_sample,
                     color=self.colors['accent'], linewidth=2, alpha=0.8)

            # Highlight anomalies
            if 'anomaly' in self.anomaly_results.columns:
                anomalies = self.anomaly_results[self.anomaly_results['anomaly'] == 1]
                anomaly_indices = [i for i in anomalies.index[:100] if i < len(data_sample)]
                if anomaly_indices:
                    anomaly_values = data_sample[anomaly_indices]
                    ax2.scatter(anomaly_indices, anomaly_values,
                                color=self.colors['danger'], s=40, zorder=5,
                                edgecolors='white', linewidth=1)

            ax2.set_title(f'Network Activity', color=self.colors['text'], fontsize=12)
            ax2.set_xlabel('Time', color=self.colors['text_secondary'])
            ax2.set_ylabel(col, color=self.colors['text_secondary'])
            ax2.tick_params(colors=self.colors['text_secondary'])
            ax2.grid(True, alpha=0.1, color=self.colors['card_border'])
            ax2.spines['bottom'].set_color(self.colors['card_border'])
            ax2.spines['top'].set_color(self.colors['card_border'])
            ax2.spines['left'].set_color(self.colors['card_border'])
            ax2.spines['right'].set_color(self.colors['card_border'])

        canvas2 = FigureCanvasTkAgg(fig2, line_inner)
        canvas2.draw()
        canvas2.get_tk_widget().pack(fill='both', expand=True)

        # Right column
        right_col = tk.Frame(main_grid, bg=self.colors['bg'])
        right_col.pack(side='right', fill='both', expand=True, padx=(10, 0))

        # IP Analysis
        ip_card = tk.Frame(right_col,
                           bg=self.colors['card'],
                           relief='flat',
                           bd=1,
                           highlightbackground=self.colors['card_border'],
                           highlightthickness=1)
        ip_card.pack(fill='x', pady=(0, 10))

        ip_inner = tk.Frame(ip_card, bg=self.colors['card'])
        ip_inner.pack(fill='x', padx=20, pady=15)

        tk.Label(ip_inner,
                 text="🌐 Top Conversations",
                 font=('Segoe UI', 13, 'bold'),
                 bg=self.colors['card'],
                 fg=self.colors['accent']).pack(anchor='w', pady=(0, 10))

        if self.ip_stats and self.ip_stats.get('most_active'):
            for idx, (ip, count) in enumerate(self.ip_stats['most_active'][:5], 1):
                ip_row = tk.Frame(ip_inner, bg=self.colors['card_border'])
                ip_row.pack(fill='x', pady=2)

                is_local = (ip == self.ip_stats.get('local_ip'))
                prefix = "🖥️ " if is_local else f"{idx}. "
                color = self.colors['accent'] if is_local else self.colors['text']

                tk.Label(ip_row,
                         text=f"{prefix}{ip}",
                         font=('Segoe UI', 10, 'bold' if is_local else 'normal'),
                         bg=self.colors['card_border'],
                         fg=color,
                         padx=10,
                         pady=4).pack(side='left')

                tk.Label(ip_row,
                         text=f"{count:,} packets",
                         font=('Segoe UI', 10),
                         bg=self.colors['card_border'],
                         fg=self.colors['text_secondary'],
                         padx=10,
                         pady=4).pack(side='right')

            if self.ip_stats.get('local_ip'):
                tk.Label(ip_inner,
                         text=f"Your IP: {self.ip_stats['local_ip']}",
                         font=('Segoe UI', 9),
                         bg=self.colors['card'],
                         fg=self.colors['text_secondary']).pack(anchor='w', pady=(5, 0))

        # Issues - With Search, Filter & Row Control
        issues_card = tk.Frame(right_col,
                               bg=self.colors['card'],
                               relief='flat',
                               bd=1,
                               highlightbackground=self.colors['card_border'],
                               highlightthickness=1)
        issues_card.pack(fill='both', expand=True)

        issues_inner = tk.Frame(issues_card, bg=self.colors['card'])
        issues_inner.pack(fill='both', expand=True, padx=20, pady=15)

        # Header with controls
        issues_header = tk.Frame(issues_inner, bg=self.colors['card'])
        issues_header.pack(fill='x')

        tk.Label(issues_header,
                 text="🔍 Issues",
                 font=('Segoe UI', 13, 'bold'),
                 bg=self.colors['card'],
                 fg=self.colors['text']).pack(side='left')

        # Report button
        report_btn = tk.Button(issues_header,
                               text="📋 Report",
                               command=self.generate_and_show_report,
                               font=('Segoe UI', 10, 'bold'),
                               bg=self.colors['accent'],
                               fg='#0a0e1a',
                               padx=15,
                               pady=5,
                               relief='flat',
                               cursor='hand2')
        report_btn.pack(side='right')

        # Search and Filter Controls
        controls_frame = tk.Frame(issues_inner, bg=self.colors['card'])
        controls_frame.pack(fill='x', pady=(10, 5))

        # Row count control
        row_frame = tk.Frame(controls_frame, bg=self.colors['card'])
        row_frame.pack(side='left', padx=(0, 10))

        tk.Label(row_frame,
                 text="Show:",
                 font=('Segoe UI', 9),
                 bg=self.colors['card'],
                 fg=self.colors['text_secondary']).pack(side='left')

        self.row_var = tk.StringVar(value="10")
        row_options = ["5", "10", "15", "20", "25", "50", "100"]
        row_menu = ttk.Combobox(row_frame,
                                textvariable=self.row_var,
                                values=row_options,
                                width=4,
                                state='readonly')
        row_menu.pack(side='left', padx=(5, 0))
        row_menu.bind('<<ComboboxSelected>>', lambda e: self.update_row_count())

        # Search box
        search_frame = tk.Frame(controls_frame, bg=self.colors['card'])
        search_frame.pack(side='left', padx=(0, 10))

        tk.Label(search_frame,
                 text="🔎",
                 font=('Segoe UI', 10),
                 bg=self.colors['card'],
                 fg=self.colors['text_secondary']).pack(side='left')

        self.search_var = tk.StringVar()
        self.search_entry = tk.Entry(search_frame,
                                     textvariable=self.search_var,
                                     font=('Segoe UI', 9),
                                     bg=self.colors['card_border'],
                                     fg=self.colors['text'],
                                     insertbackground=self.colors['text'],
                                     width=15)
        self.search_entry.pack(side='left', padx=(5, 0))
        self.search_entry.bind('<KeyRelease>', lambda e: self.on_search())

        # Filter type dropdown
        filter_frame = tk.Frame(controls_frame, bg=self.colors['card'])
        filter_frame.pack(side='left', padx=(0, 10))

        tk.Label(filter_frame,
                 text="Filter:",
                 font=('Segoe UI', 9),
                 bg=self.colors['card'],
                 fg=self.colors['text_secondary']).pack(side='left')

        self.filter_var = tk.StringVar(value="All")
        filter_options = ["All", "IP", "Protocol", "Port"]
        filter_menu = ttk.Combobox(filter_frame,
                                   textvariable=self.filter_var,
                                   values=filter_options,
                                   width=8,
                                   state='readonly')
        filter_menu.pack(side='left', padx=(5, 0))
        filter_menu.bind('<<ComboboxSelected>>', lambda e: self.apply_filters())

        # Clear filter button
        clear_btn = tk.Button(controls_frame,
                              text="Clear",
                              command=self.clear_filters,
                              font=('Segoe UI', 8),
                              bg=self.colors['card_border'],
                              fg=self.colors['text_secondary'],
                              relief='flat',
                              cursor='hand2',
                              padx=8,
                              pady=2)
        clear_btn.pack(side='left')

        # Results count
        self.result_count_label = tk.Label(controls_frame,
                                           text="",
                                           font=('Segoe UI', 9),
                                           bg=self.colors['card'],
                                           fg=self.colors['text_secondary'])
        self.result_count_label.pack(side='right')

        # Issues list container
        self.issues_container = tk.Frame(issues_inner, bg=self.colors['card'])
        self.issues_container.pack(fill='both', expand=True, pady=(5, 0))

        # Show issues
        self.show_filtered_issues(self.issues_container)

    def show_filtered_issues(self, container):
        """Display filtered issues"""
        # Clear container
        for widget in container.winfo_children():
            widget.destroy()

        if self.filtered_anomalies is None or len(self.filtered_anomalies) == 0:
            tk.Label(container,
                     text="No issues found matching your criteria",
                     font=('Segoe UI', 12),
                     bg=self.colors['card'],
                     fg=self.colors['text_secondary']).pack(pady=30)
            return

        # Get display count
        try:
            display_count = int(self.row_var.get())
        except:
            display_count = 10

        # Get anomalies to display
        anomalies_to_show = self.filtered_anomalies.head(display_count)
        total_anomalies = len(self.filtered_anomalies)

        # Update result count
        self.result_count_label.config(text=f"Showing {len(anomalies_to_show)} of {total_anomalies}")

        # Create canvas with scrollbar
        canvas = tk.Canvas(container, bg=self.colors['card'], highlightthickness=0)
        scrollbar = tk.Scrollbar(container, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=self.colors['card'])

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # Find columns to display
        display_cols = []
        important_cols = ['src_ip', 'dst_ip', 'source_ip', 'destination_ip',
                          'protocol', 'time', 'timestamp', 'packet_size', 'size',
                          'length', 'bytes', 'port', 'src_port', 'dst_port']

        for col in important_cols:
            if col in anomalies_to_show.columns:
                display_cols.append(col)

        if not display_cols:
            display_cols = list(anomalies_to_show.columns[:3])

        # Show issues with details
        for idx, (row_idx, row) in enumerate(anomalies_to_show.iterrows()):
            issue_item = tk.Frame(scrollable_frame, bg=self.colors['card_border'])
            issue_item.pack(fill='x', pady=2)

            issue_inner = tk.Frame(issue_item, bg=self.colors['card_border'])
            issue_inner.pack(fill='x', padx=10, pady=5)

            # Issue number
            tk.Label(issue_inner,
                     text=f"#{idx + 1}",
                     font=('Segoe UI', 10, 'bold'),
                     bg=self.colors['card_border'],
                     fg=self.colors['danger'],
                     width=4).pack(side='left')

            # Show column values
            col_values = []
            for col in display_cols[:4]:
                if col in row and pd.notna(row[col]):
                    value = str(row[col])
                    if len(value) > 20:
                        value = value[:17] + "..."
                    col_values.append(f"{col}: {value}")

            if col_values:
                display_text = " | ".join(col_values)
                tk.Label(issue_inner,
                         text=display_text,
                         font=('Segoe UI', 9),
                         bg=self.colors['card_border'],
                         fg=self.colors['text'],
                         anchor='w').pack(side='left', fill='x', expand=True, padx=(5, 0))
            else:
                tk.Label(issue_inner,
                         text=f"Record {row_idx}",
                         font=('Segoe UI', 9),
                         bg=self.colors['card_border'],
                         fg=self.colors['text'],
                         anchor='w').pack(side='left', fill='x', expand=True, padx=(5, 0))

            # Severity indicator
            if 'anomaly_score' in row and pd.notna(row['anomaly_score']):
                score = row['anomaly_score']
                score_pct = min(100, max(0, (score + 1) * 50))
                if score_pct > 70:
                    indicator = "🔴"
                elif score_pct > 40:
                    indicator = "🟡"
                else:
                    indicator = "🟢"

                tk.Label(issue_inner,
                         text=indicator,
                         font=('Segoe UI', 10),
                         bg=self.colors['card_border'],
                         fg=self.colors['text']).pack(side='right', padx=(5, 0))

        # Show count if more
        if total_anomalies > display_count:
            tk.Label(scrollable_frame,
                     text=f"... and {total_anomalies - display_count} more issues",
                     font=('Segoe UI', 9),
                     bg=self.colors['card'],
                     fg=self.colors['text_secondary']).pack(pady=5)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def update_row_count(self):
        """Update the number of rows displayed"""
        self.apply_filters()

    def on_search(self):
        """Handle search input"""
        self.search_term = self.search_var.get().strip()
        self.apply_filters()

    def clear_filters(self):
        """Clear all filters and search"""
        self.search_var.set("")
        self.search_term = ""
        self.filter_var.set("All")
        self.filter_type = "All"
        self.apply_filters()

    def generate_and_show_report(self):
        """Generate clean report"""
        if self.anomaly_results is None:
            return

        anomaly_count = self.anomaly_results['anomaly'].sum()
        total_records = len(self.data)
        health_score = 100 - (anomaly_count / total_records * 100)

        report_lines = []

        report_lines.append("")
        report_lines.append("NETWORK HEALTH REPORT")
        report_lines.append("")
        report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        report_lines.append("")

        report_lines.append("HEALTH SUMMARY")
        report_lines.append("────────────────────────────────────────")
        report_lines.append(f"Health Score: {health_score:.0f}%")
        report_lines.append(f"Records Analyzed: {total_records:,}")
        report_lines.append(f"Issues Found: {anomaly_count:,}")
        report_lines.append(f"Issue Rate: {anomaly_count / total_records * 100:.1f}%")
        report_lines.append("")

        if health_score >= 85:
            report_lines.append("✅ Status: Excellent")
            report_lines.append("Network is operating normally.")
        elif health_score >= 60:
            report_lines.append("⚠️ Status: Fair")
            report_lines.append("Some unusual patterns detected.")
        else:
            report_lines.append("🔴 Status: Needs Attention")
            report_lines.append("Significant issues detected.")
        report_lines.append("")

        if self.ip_stats:
            report_lines.append("IP CONVERSATIONS")
            report_lines.append("────────────────────────────────────────")
            report_lines.append(f"Total Unique IPs: {self.ip_stats['total_unique_ips']}")
            if self.ip_stats.get('local_ip'):
                report_lines.append(f"Your IP: {self.ip_stats['local_ip']}")
            report_lines.append("")

            report_lines.append("Most Active IPs:")
            for ip, count in self.ip_stats['most_active'][:5]:
                marker = " (Your IP)" if ip == self.ip_stats.get('local_ip') else ""
                report_lines.append(f"  • {ip}{marker}: {count:,} packets")
            report_lines.append("")

        if anomaly_count > 0:
            report_lines.append("ANOMALIES")
            report_lines.append("────────────────────────────────────────")
            anomalies = self.anomaly_results[self.anomaly_results['anomaly'] == 1]
            report_lines.append(f"Total: {len(anomalies):,}")
            report_lines.append("")

            display_cols = []
            important_cols = ['src_ip', 'dst_ip', 'protocol', 'time', 'timestamp',
                              'packet_size', 'size', 'length', 'bytes', 'port']

            for col in important_cols:
                if col in anomalies.columns:
                    display_cols.append(col)

            if not display_cols:
                display_cols = list(anomalies.columns[:3])

            for idx, (_, row) in enumerate(anomalies.head(10).iterrows(), 1):
                report_lines.append(f"  #{idx}:")
                for col in display_cols[:4]:
                    if col in row and pd.notna(row[col]):
                        report_lines.append(f"    {col}: {row[col]}")
                report_lines.append("")

        report_lines.append("RECOMMENDATIONS")
        report_lines.append("────────────────────────────────────────")

        if health_score >= 85:
            report_lines.append("• Continue regular monitoring")
            report_lines.append("• Review settings quarterly")
        elif health_score >= 60:
            report_lines.append("• Review detected issues")
            report_lines.append("• Check for unusual patterns")
        else:
            report_lines.append("• IMMEDIATE: Review critical issues")
            report_lines.append("• Check for security breaches")
            report_lines.append("• Consult IT security team")

        report_lines.append("")
        report_lines.append("Report generated by Network Health Monitor")

        self.report_content = "\n".join(report_lines)
        self.show_report_window()

    def show_report_window(self):
        """Display report with download option"""
        report_window = tk.Toplevel(self.root)
        report_window.title("Network Health Report")
        report_window.geometry("700x600")
        report_window.configure(bg='#0a0e1a')
        report_window.transient(self.root)
        report_window.grab_set()

        main_frame = tk.Frame(report_window, bg='#0a0e1a')
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)

        # Header
        header = tk.Frame(main_frame, bg='#0a0e1a')
        header.pack(fill='x', pady=(0, 10))

        tk.Label(header,
                 text="Network Health Report",
                 font=('Segoe UI', 18, 'bold'),
                 bg='#0a0e1a',
                 fg='#00d4ff').pack(side='left')

        btn_frame = tk.Frame(header, bg='#0a0e1a')
        btn_frame.pack(side='right')

        download_btn = tk.Button(btn_frame,
                                 text="💾 Download",
                                 command=self.download_report,
                                 font=('Segoe UI', 10, 'bold'),
                                 bg='#00ff88',
                                 fg='#0a0e1a',
                                 padx=15,
                                 pady=5,
                                 relief='flat',
                                 cursor='hand2')
        download_btn.pack(side='left', padx=(0, 5))

        close_btn = tk.Button(btn_frame,
                              text="✕ Close",
                              command=report_window.destroy,
                              font=('Segoe UI', 10),
                              bg='#ff4757',
                              fg='white',
                              padx=15,
                              pady=5,
                              relief='flat',
                              cursor='hand2')
        close_btn.pack(side='left')

        text_frame = tk.Frame(main_frame, bg='#141b2d', relief='flat', bd=1,
                              highlightbackground='#1f2a42', highlightthickness=1)
        text_frame.pack(fill='both', expand=True)

        text_widget = scrolledtext.ScrolledText(text_frame,
                                                font=('Consolas', 10),
                                                bg='#141b2d',
                                                fg='#e0e6ed',
                                                insertbackground='#e0e6ed',
                                                wrap=tk.WORD,
                                                padx=15,
                                                pady=15)
        text_widget.pack(fill='both', expand=True)
        text_widget.insert('1.0', self.report_content)
        text_widget.configure(state='disabled')

    def download_report(self):
        """Download report to file"""
        if not self.report_content:
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("Markdown files", "*.md")],
            initialfile=f"network_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )

        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.report_content)
                messagebox.showinfo("Success", f"Report saved to:\n{filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save report:\n{str(e)}")

    def clear_main(self):
        """Clear main container"""
        for widget in self.main_container.winfo_children():
            widget.destroy()


def main():
    root = tk.Tk()
    app = NetworkHealthMonitor(root)
    root.mainloop()


if __name__ == "__main__":
    main()